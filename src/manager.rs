//! User-level Manager and relay-child lifecycle contracts for RSB-2.
//!
//! This module owns local session resolution, non-secret fingerprint persistence, bounded lease
//! bookkeeping, controlled child bootstrap, and safe LaunchAgent rendering. It deliberately does
//! not expose a Broker listener, parse Herdr payloads, or connect Core/App transports.

use crate::{
    broker::{
        BROKER_DATA_PORT_BASE, BROKER_DATA_PORT_LAST, BROKER_DISCOVERY_PORT_ATTEMPTS,
        BROKER_DISCOVERY_PORT_BASE, BROKER_DISCOVERY_PORT_LAST,
    },
    config::{V1_BUFFER_BYTES, V1_IDLE_TIMEOUT_SECS, validate_absolute_path},
    error::{RelayError, RelayResult},
    socket::{UnixSocketConnector, UnixSocketIdentity},
};
use fs2::FileExt;
use rand::random;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    time::{self, timeout},
};

/// The complete commented RSB-2 Manager configuration template.
pub const DEFAULT_MANAGER_CONFIG_TOML: &str = include_str!("../config/manager-default.toml");
/// The Manager-owned state file name.
pub const MANAGER_STATE_FILE: &str = "state.json";
/// The per-session non-secret fingerprint file name.
pub const SESSION_FINGERPRINT_FILE: &str = ".herdr-dog-session-fingerprint";
/// The Manager-owned session configuration file name.
pub const SESSION_RELAY_CONFIG_FILE: &str = "relay.toml";
/// The user-level LaunchAgent label rendered by this milestone.
pub const LAUNCH_AGENT_LABEL: &str = "dev.herdr-dog.herdogrelay-manager";
/// The maximum duration allowed for child bootstrap IPC.
pub const CHILD_BOOTSTRAP_TIMEOUT_SECS: u64 = 5;
/// The fixed lease heartbeat interval selected by the RSB plan.
pub const MANAGER_HEARTBEAT_INTERVAL_SECS: u64 = 30;
/// The fixed lease expiry interval selected by the RSB plan.
pub const MANAGER_LEASE_EXPIRY_SECS: u64 = 90;
/// The fixed child idle grace selected by the RSB plan.
pub const MANAGER_IDLE_GRACE_SECS: u64 = 300;
/// The maximum text size accepted for a persisted fingerprint.
pub const FINGERPRINT_TEXT_BYTES: usize = 64;

const CHILD_BOOTSTRAP_MAGIC: [u8; 4] = *b"HDBI";
const CHILD_BOOTSTRAP_VERSION: u16 = 1;
const CHILD_ACK: [u8; 5] = *b"HDBA\0";
const MAX_CHILD_FRAME_BYTES: usize = 4 + 2 + 32 + 8 + 2 + 1 + 64;

/// A normalized Herdr session name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionName(String);

impl fmt::Debug for SessionName {
    /// Render the normalized non-secret session name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SessionName").field(&self.0).finish()
    }
}

impl SessionName {
    /// Normalize an App/Manager session value, mapping empty input to `default`.
    ///
    /// # Arguments
    ///
    /// * `value` - The caller-provided session name.
    ///
    /// # Returns
    ///
    /// A source-aligned normalized session name or a stable validation error.
    pub fn normalize(value: &str) -> RelayResult<Self> {
        let value = if value.is_empty() { "default" } else { value };
        if value.len() > 64
            || value == "."
            || value == ".."
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        {
            return Err(RelayError::InvalidConfiguration {
                field: "session",
                reason: "must be default or 1..64 ASCII letters, numbers, '.', '_' or '-'",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical wire/path component.
    ///
    /// # Returns
    ///
    /// The normalized session string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this is Herdr's default session.
    ///
    /// # Returns
    ///
    /// `true` only for the canonical `default` name.
    pub fn is_default(&self) -> bool {
        self.0 == "default"
    }
}

/// A 32-byte session fingerprint retained only in memory by Manager operations.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SessionFingerprint([u8; 32]);

impl fmt::Debug for SessionFingerprint {
    /// Render presence without exposing fingerprint bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionFingerprint")
            .field("present", &true)
            .finish()
    }
}

impl SessionFingerprint {
    /// Construct an opaque fingerprint from fixed-width bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte fingerprint retained in memory.
    ///
    /// # Returns
    ///
    /// A typed fingerprint without exposing its contents in diagnostics.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width fingerprint bytes for an internal authority frame.
    ///
    /// # Returns
    ///
    /// The 32-byte fingerprint; callers must not log or persist the bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate a cryptographically seeded opaque fingerprint for a new session directory.
    fn generate() -> Self {
        Self(random())
    }
}

/// A 32-byte lease token retained only in Manager/child memory.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaseToken([u8; 32]);

impl fmt::Debug for LeaseToken {
    /// Render presence without exposing token bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseToken")
            .field("present", &true)
            .finish()
    }
}

impl LeaseToken {
    /// Construct an opaque lease token from fixed-width bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte token delivered through protected control/data boundaries.
    ///
    /// # Returns
    ///
    /// A typed token without exposing its contents in diagnostics.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width token bytes for an internal authority frame.
    ///
    /// # Returns
    ///
    /// The 32-byte token; callers must not log or persist the bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generate an unpredictable in-memory lease token.
    fn generate() -> Self {
        Self(random())
    }
}

/// Validated Manager configuration with immutable RSB-2 policy values.
pub struct ManagerConfig {
    /// Manager-owned state and generated session configuration directory.
    manager_root: PathBuf,
    /// Herdr configuration root containing the `herdr` directory.
    herdr_config_root: PathBuf,
    /// Absolute path of the same binary used for controlled child mode.
    child_binary: PathBuf,
    /// Persisted preferred Broker discovery port.
    preferred_broker_port: u16,
    /// Fixed Broker discovery candidate count.
    broker_port_attempts: u16,
    /// First session data port.
    data_port_start: u16,
    /// Last session data port.
    data_port_end: u16,
    /// Fixed lease heartbeat interval.
    heartbeat_interval: Duration,
    /// Fixed lease expiry interval.
    lease_expiry: Duration,
    /// Fixed idle grace interval.
    idle_grace: Duration,
}

impl fmt::Debug for ManagerConfig {
    /// Render policy and path presence without exposing user paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagerConfig")
            .field("manager_root_present", &true)
            .field("herdr_config_root_present", &true)
            .field("child_binary_present", &true)
            .field("preferred_broker_port", &self.preferred_broker_port)
            .field("broker_port_attempts", &self.broker_port_attempts)
            .field(
                "data_port_range",
                &(self.data_port_start, self.data_port_end),
            )
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("lease_expiry", &self.lease_expiry)
            .field("idle_grace", &self.idle_grace)
            .finish()
    }
}

/// Private TOML shape used to validate all Manager configuration inputs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerConfigWire {
    /// Manager root or the `auto` sentinel.
    #[serde(default = "auto_path")]
    manager_root: PathBuf,
    /// Herdr config root or the `auto` sentinel.
    #[serde(default = "auto_path")]
    herdr_config_root: PathBuf,
    /// Child binary or the `auto` sentinel.
    #[serde(default = "auto_path")]
    child_binary: PathBuf,
    /// Persisted preferred Broker discovery port.
    #[serde(default = "default_preferred_broker_port")]
    preferred_broker_port: u16,
    /// Broker discovery attempt count.
    #[serde(default = "default_broker_port_attempts")]
    broker_port_attempts: u16,
    /// First data port.
    #[serde(default = "default_data_port_start")]
    data_port_start: u16,
    /// Last data port.
    #[serde(default = "default_data_port_end")]
    data_port_end: u16,
    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_secs")]
    heartbeat_interval_secs: u64,
    /// Lease expiry in seconds.
    #[serde(default = "default_lease_expiry_secs")]
    lease_expiry_secs: u64,
    /// Idle grace in seconds.
    #[serde(default = "default_idle_grace_secs")]
    idle_grace_secs: u64,
}

impl ManagerConfig {
    /// Parse and validate a Manager TOML string using the current environment for `auto` values.
    ///
    /// # Arguments
    ///
    /// * `input` - Complete UTF-8 Manager TOML.
    ///
    /// # Returns
    ///
    /// A validated Manager configuration or a redacted configuration error.
    pub fn from_toml_str(input: &str) -> RelayResult<Self> {
        let wire: ManagerConfigWire =
            toml::from_str(input).map_err(|_| RelayError::ConfigurationSyntax)?;
        Self::from_wire(wire, None)
    }

    /// Read and validate a Manager TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Manager configuration file path.
    ///
    /// # Returns
    ///
    /// A validated Manager configuration or a redacted read/configuration error.
    pub fn from_path(path: &Path) -> RelayResult<Self> {
        let input = fs::read_to_string(path)
            .map_err(|error| RelayError::io("reading manager configuration", error))?;
        let wire: ManagerConfigWire =
            toml::from_str(&input).map_err(|_| RelayError::ConfigurationSyntax)?;
        Self::from_wire(wire, path.parent())
    }

    /// Build a validated configuration from its private wire shape.
    fn from_wire(wire: ManagerConfigWire, config_parent: Option<&Path>) -> RelayResult<Self> {
        let manager_root = resolve_path(
            wire.manager_root,
            config_parent
                .map(Path::to_path_buf)
                .or_else(default_manager_root),
            "manager_root",
        )?;
        let herdr_config_root = resolve_path(
            wire.herdr_config_root,
            default_herdr_config_root(),
            "herdr_config_root",
        )?;
        let child_binary = resolve_path(
            wire.child_binary,
            std::env::current_exe().ok(),
            "child_binary",
        )?;
        let config = Self {
            manager_root,
            herdr_config_root,
            child_binary,
            preferred_broker_port: wire.preferred_broker_port,
            broker_port_attempts: wire.broker_port_attempts,
            data_port_start: wire.data_port_start,
            data_port_end: wire.data_port_end,
            heartbeat_interval: Duration::from_secs(wire.heartbeat_interval_secs),
            lease_expiry: Duration::from_secs(wire.lease_expiry_secs),
            idle_grace: Duration::from_secs(wire.idle_grace_secs),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate all fixed RSB-2 values and path boundaries.
    ///
    /// # Returns
    ///
    /// `Ok(())` only when the configuration cannot widen the frozen policy.
    pub fn validate(&self) -> RelayResult<()> {
        validate_absolute_path("manager_root", &self.manager_root)?;
        validate_absolute_path("herdr_config_root", &self.herdr_config_root)?;
        validate_absolute_path("child_binary", &self.child_binary)?;
        let checks = [
            (
                "preferred_broker_port",
                (BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST)
                    .contains(&self.preferred_broker_port),
                "must remain in the v1 Broker discovery range",
            ),
            (
                "broker_port_attempts",
                self.broker_port_attempts == BROKER_DISCOVERY_PORT_ATTEMPTS,
                "must remain the v1 value 10",
            ),
            (
                "data_port_start",
                self.data_port_start == BROKER_DATA_PORT_BASE,
                "must remain the RSB data-port start",
            ),
            (
                "data_port_end",
                self.data_port_end == BROKER_DATA_PORT_LAST,
                "must remain the RSB data-port end",
            ),
            (
                "heartbeat_interval_secs",
                self.heartbeat_interval == Duration::from_secs(MANAGER_HEARTBEAT_INTERVAL_SECS),
                "must remain the RSB value 30",
            ),
            (
                "lease_expiry_secs",
                self.lease_expiry == Duration::from_secs(MANAGER_LEASE_EXPIRY_SECS),
                "must remain the RSB value 90",
            ),
            (
                "idle_grace_secs",
                self.idle_grace == Duration::from_secs(MANAGER_IDLE_GRACE_SECS),
                "must remain the RSB value 300",
            ),
        ];
        for (field, valid, reason) in checks {
            if !valid {
                return Err(RelayError::InvalidConfiguration { field, reason });
            }
        }
        Ok(())
    }

    /// Render the user-level LaunchAgent plist for this Manager binary.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Absolute Manager TOML path passed to the process.
    ///
    /// # Returns
    ///
    /// A bounded XML plist without runtime secrets.
    pub fn launch_agent_plist(&self, config_path: &Path) -> RelayResult<String> {
        validate_absolute_path("manager_config", config_path)?;
        render_launch_agent(&self.child_binary, config_path)
    }

    /// Return the Manager-owned root.
    pub fn manager_root(&self) -> &Path {
        &self.manager_root
    }

    /// Return the Herdr configuration root.
    pub fn herdr_config_root(&self) -> &Path {
        &self.herdr_config_root
    }

    /// Return the controlled child binary path.
    pub fn child_binary(&self) -> &Path {
        &self.child_binary
    }

    /// Return the persisted preferred Broker discovery port.
    pub fn preferred_broker_port(&self) -> u16 {
        self.preferred_broker_port
    }

    /// Return the configured data-port range.
    pub fn data_port_range(&self) -> (u16, u16) {
        (self.data_port_start, self.data_port_end)
    }

    /// Return the lease heartbeat interval.
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Return the lease expiry interval.
    pub fn lease_expiry(&self) -> Duration {
        self.lease_expiry
    }

    /// Return the child idle grace interval.
    pub fn idle_grace(&self) -> Duration {
        self.idle_grace
    }
}

/// A resolved existing Herdr session and its validated socket identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedSession {
    /// Canonical session name.
    session: SessionName,
    /// Existing Herdr session directory.
    directory: PathBuf,
    /// Existing Herdr API socket path.
    socket: PathBuf,
    /// Socket identity captured before lease acquisition.
    socket_identity: UnixSocketIdentity,
}

impl fmt::Debug for ResolvedSession {
    /// Render session and identity presence without exposing filesystem paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSession")
            .field("session", &self.session)
            .field("directory_present", &true)
            .field("socket_present", &true)
            .field("socket_identity_present", &true)
            .finish()
    }
}

impl ResolvedSession {
    /// Return the canonical session name.
    pub fn session(&self) -> &SessionName {
        &self.session
    }

    /// Return the validated socket identity.
    pub fn socket_identity(&self) -> UnixSocketIdentity {
        self.socket_identity
    }

    /// Return the fingerprint file location for internal persistence.
    fn fingerprint_path(&self) -> PathBuf {
        self.directory.join(SESSION_FINGERPRINT_FILE)
    }

    /// Return the generated Relay configuration location for this session.
    fn relay_config_path(&self, manager_root: &Path) -> PathBuf {
        manager_root
            .join("sessions")
            .join(self.session.as_str())
            .join(SESSION_RELAY_CONFIG_FILE)
    }
}

/// Map a missing configured Herdr socket to the stable readiness category.
fn map_missing_socket<T>(result: RelayResult<T>) -> RelayResult<T> {
    result.map_err(|error| match error {
        RelayError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        } => RelayError::UpstreamUnavailable,
        other => other,
    })
}

/// Source-aligned resolver for existing default and named Herdr sessions.
#[derive(Clone, Debug)]
pub struct HerdrSessionResolver {
    /// The config root containing Herdr's `herdr` directory.
    config_root: PathBuf,
    /// The UID required for session directories and API sockets.
    expected_uid: u32,
}

impl HerdrSessionResolver {
    /// Create a resolver with a fixed config root and expected user owner.
    ///
    /// # Arguments
    ///
    /// * `config_root` - The absolute root containing the `herdr` directory.
    /// * `expected_uid` - The user UID that must own the session path.
    ///
    /// # Returns
    ///
    /// A resolver with validated path configuration.
    pub fn new(config_root: impl Into<PathBuf>, expected_uid: u32) -> RelayResult<Self> {
        let config_root = config_root.into();
        validate_absolute_path("herdr_config_root", &config_root)?;
        Ok(Self {
            config_root,
            expected_uid,
        })
    }

    /// Resolve an already existing default or named session without invoking Herdr CLI.
    ///
    /// # Arguments
    ///
    /// * `session` - The normalized session name.
    ///
    /// # Returns
    ///
    /// A session directory and socket identity, or a stable unavailable/identity error.
    pub fn resolve(&self, session: &SessionName) -> RelayResult<ResolvedSession> {
        let herdr_root = self.config_root.join(herdr_app_dir());
        let directory = if session.is_default() {
            herdr_root.clone()
        } else {
            herdr_root.join("sessions").join(session.as_str())
        };
        validate_existing_path_components(&directory)?;
        let metadata =
            fs::symlink_metadata(&directory).map_err(|_| RelayError::UpstreamUnavailable)?;
        if !metadata.is_dir() || metadata.uid() != self.expected_uid {
            return Err(RelayError::SocketIdentity {
                operation: "checking Herdr session directory",
                reason: "session directory owner or type is invalid",
            });
        }
        let socket = directory.join("herdr.sock");
        let connector = UnixSocketConnector::new(&socket, self.expected_uid)?;
        let socket_identity = map_missing_socket(connector.validate())?;
        Ok(ResolvedSession {
            session: session.clone(),
            directory,
            socket,
            socket_identity,
        })
    }

    /// Confirm the validated socket is reachable without sending Herdr protocol bytes.
    ///
    /// # Arguments
    ///
    /// * `session` - A previously resolved session.
    ///
    /// # Returns
    ///
    /// `Ok(())` after a connect-and-close probe, or a redacted availability error.
    pub async fn verify_reachable(&self, session: &ResolvedSession) -> RelayResult<()> {
        let connector = UnixSocketConnector::new(&session.socket, self.expected_uid)?;
        let stream = map_missing_socket(connector.connect_checked(session.socket_identity).await)?;
        drop(stream);
        Ok(())
    }
}

/// Persistent non-secret fingerprint storage for existing session directories.
#[derive(Clone, Copy, Debug)]
pub struct FingerprintStore {
    /// The UID required for the fingerprint file and session directory.
    expected_uid: u32,
}

impl FingerprintStore {
    /// Create a fingerprint store for one user owner.
    pub fn new(expected_uid: u32) -> Self {
        Self { expected_uid }
    }

    /// Read an existing fingerprint or atomically create one with mode 0600.
    ///
    /// # Arguments
    ///
    /// * `session` - A resolver-validated existing session.
    ///
    /// # Returns
    ///
    /// A non-secret in-memory fingerprint, never the raw file text.
    pub fn load_or_create(&self, session: &ResolvedSession) -> RelayResult<SessionFingerprint> {
        let path = session.fingerprint_path();
        if path.exists() {
            return self.read(&path);
        }
        let fingerprint = SessionFingerprint::generate();
        match create_private_file(&path, &encode_fingerprint(fingerprint), 0o600) {
            Ok(()) => Ok(fingerprint),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => self.read(&path),
            Err(error) => Err(RelayError::io("creating session fingerprint", error)),
        }
    }

    /// Read and validate one existing fingerprint file.
    fn read(&self, path: &Path) -> RelayResult<SessionFingerprint> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| RelayError::io("reading session fingerprint", error))?;
        if metadata.uid() != self.expected_uid
            || metadata.permissions().mode() & 0o777 != 0o600
            || !metadata.is_file()
        {
            return Err(RelayError::InvalidFingerprint);
        }
        let bytes =
            fs::read(path).map_err(|error| RelayError::io("reading session fingerprint", error))?;
        decode_fingerprint(&bytes)
    }
}

/// A bounded data-port allocator for Manager-owned session slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataPortAllocator {
    /// First allowed port.
    start: u16,
    /// Last allowed port.
    end: u16,
    /// Ports currently retained by live child slots.
    allocated: BTreeSet<u16>,
}

impl DataPortAllocator {
    /// Create an allocator and reject any range outside the frozen RSB range.
    pub fn new(start: u16, end: u16) -> RelayResult<Self> {
        if start != BROKER_DATA_PORT_BASE || end != BROKER_DATA_PORT_LAST {
            return Err(RelayError::InvalidConfiguration {
                field: "data_port_range",
                reason: "must remain 18753..18852",
            });
        }
        Ok(Self {
            start,
            end,
            allocated: BTreeSet::new(),
        })
    }

    /// Reserve the first free data port in ascending order.
    pub fn reserve(&mut self) -> RelayResult<u16> {
        let port = (self.start..=self.end)
            .find(|port| !self.allocated.contains(port))
            .ok_or(RelayError::PortRangeExhausted)?;
        self.allocated.insert(port);
        Ok(port)
    }

    /// Release one previously reserved data port.
    pub fn release(&mut self, port: u16) {
        self.allocated.remove(&port);
    }

    /// Return whether a data port is currently reserved.
    pub fn contains(&self, port: u16) -> bool {
        self.allocated.contains(&port)
    }
}

/// A controlled child launch request. The token is sent only over bootstrap IPC.
#[derive(Clone)]
pub struct ChildSpec {
    /// Canonical session assigned to the child.
    session: SessionName,
    /// Manager-owned child generation.
    generation: u64,
    /// Manager-reserved data port.
    data_port: u16,
    /// Protected IPC endpoint used for the in-memory token bootstrap.
    ipc_path: PathBuf,
    /// Manager process ID used for bounded parent-death cleanup.
    parent_pid: u32,
    /// Opaque lease token delivered after the child connects.
    token: LeaseToken,
}

impl fmt::Debug for ChildSpec {
    /// Render child metadata without token or full filesystem paths.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildSpec")
            .field("session", &self.session)
            .field("generation", &self.generation)
            .field("data_port", &self.data_port)
            .field("parent_pid", &self.parent_pid)
            .field("ipc_path_present", &true)
            .field("token", &self.token)
            .finish()
    }
}

impl ChildSpec {
    /// Return the canonical child session.
    pub fn session(&self) -> &SessionName {
        &self.session
    }

    /// Return the child generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the reserved data port.
    pub fn data_port(&self) -> u16 {
        self.data_port
    }
}

/// A bounded child process handle owned by Manager.
pub struct ChildHandle {
    /// Process ID or deterministic fake ID.
    pid: u32,
    /// Child generation.
    generation: u64,
    /// Reserved data port.
    data_port: u16,
    /// Actual or fake process state.
    kind: ChildKind,
}

enum ChildKind {
    /// A real child process started by this Manager.
    Process(Child),
    /// A deterministic local fake child used by contract tests.
    Fake,
}

impl fmt::Debug for ChildHandle {
    /// Render process metadata without command lines or tokens.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildHandle")
            .field("pid", &self.pid)
            .field("generation", &self.generation)
            .field("data_port", &self.data_port)
            .finish()
    }
}

impl ChildHandle {
    /// Return the child process ID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Return the child generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the reserved data port.
    pub fn data_port(&self) -> u16 {
        self.data_port
    }
}

/// A boxed asynchronous child lifecycle result.
pub type ChildFuture<'a, T> = Pin<Box<dyn Future<Output = RelayResult<T>> + Send + 'a>>;

/// The controlled child lifecycle seam used by Manager and its fake tests.
pub trait ChildSpawner: Send + Sync {
    /// Start one child and complete only after protected bootstrap acknowledgement.
    fn spawn<'a>(&'a self, spec: ChildSpec) -> ChildFuture<'a, ChildHandle>;
    /// Stop one Manager-owned child and wait for its process to exit.
    fn stop<'a>(&'a self, child: &'a mut ChildHandle) -> ChildFuture<'a, ()>;
    /// Check whether one child is still alive without exposing process diagnostics.
    fn is_alive(&self, child: &mut ChildHandle) -> bool;
}

/// The production same-binary child spawner.
#[derive(Clone, Debug)]
pub struct ProcessChildSpawner {
    /// Absolute executable path selected by Manager configuration.
    binary: PathBuf,
}

impl ProcessChildSpawner {
    /// Create a production child spawner for an absolute binary path.
    pub fn new(binary: impl Into<PathBuf>) -> RelayResult<Self> {
        let binary = binary.into();
        validate_absolute_path("child_binary", &binary)?;
        Ok(Self { binary })
    }
}

impl ChildSpawner for ProcessChildSpawner {
    /// Spawn the same binary in controlled `relay-child` mode and complete bootstrap IPC.
    fn spawn<'a>(&'a self, spec: ChildSpec) -> ChildFuture<'a, ChildHandle> {
        Box::pin(async move {
            validate_data_port(spec.data_port)?;
            validate_ipc_path(&spec.ipc_path)?;
            let frame = ChildBootstrap::encode(&spec)?;
            let _ = fs::remove_file(&spec.ipc_path);
            let listener = UnixListener::bind(&spec.ipc_path)
                .map_err(|error| RelayError::io("binding child bootstrap IPC", error))?;
            if let Err(error) =
                fs::set_permissions(&spec.ipc_path, fs::Permissions::from_mode(0o600))
            {
                let _ = fs::remove_file(&spec.ipc_path);
                return Err(RelayError::io("protecting child bootstrap IPC", error));
            }
            let mut child = match Command::new(&self.binary)
                .arg("relay-child")
                .arg("--ipc")
                .arg(&spec.ipc_path)
                .arg("--session")
                .arg(spec.session.as_str())
                .arg("--generation")
                .arg(spec.generation.to_string())
                .arg("--data-port")
                .arg(spec.data_port.to_string())
                .arg("--parent-pid")
                .arg(spec.parent_pid.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
            {
                Ok(child) => child,
                Err(error) => {
                    let _ = fs::remove_file(&spec.ipc_path);
                    return Err(RelayError::io("starting relay child", error));
                }
            };
            let accepted = match timeout(
                Duration::from_secs(CHILD_BOOTSTRAP_TIMEOUT_SECS),
                listener.accept(),
            )
            .await
            {
                Ok(Ok(accepted)) => accepted,
                Ok(Err(error)) => {
                    terminate_child_after_bootstrap_failure(&mut child, &spec.ipc_path).await;
                    return Err(RelayError::io("accepting child bootstrap IPC", error));
                }
                Err(_) => {
                    terminate_child_after_bootstrap_failure(&mut child, &spec.ipc_path).await;
                    return Err(RelayError::ChildLifecycle {
                        reason: "child bootstrap timed out",
                    });
                }
            };
            let (mut stream, _) = accepted;
            if let Err(error) = exchange_child_bootstrap(
                &mut stream,
                &frame,
                Duration::from_secs(CHILD_BOOTSTRAP_TIMEOUT_SECS),
            )
            .await
            {
                terminate_child_after_bootstrap_failure(&mut child, &spec.ipc_path).await;
                return Err(error);
            }
            let _ = fs::remove_file(&spec.ipc_path);
            Ok(ChildHandle {
                pid: child.id().unwrap_or_default(),
                generation: spec.generation,
                data_port: spec.data_port,
                kind: ChildKind::Process(child),
            })
        })
    }

    /// Terminate one process child and wait for its exit.
    fn stop<'a>(&'a self, child: &'a mut ChildHandle) -> ChildFuture<'a, ()> {
        Box::pin(async move {
            if let ChildKind::Process(process) = &mut child.kind {
                if process
                    .try_wait()
                    .map_err(|error| RelayError::io("checking relay child", error))?
                    .is_some()
                {
                    return Ok(());
                }
                process
                    .kill()
                    .await
                    .map_err(|error| RelayError::io("stopping relay child", error))?;
                process
                    .wait()
                    .await
                    .map_err(|error| RelayError::io("waiting for relay child", error))?;
            }
            Ok(())
        })
    }

    /// Check real process state through the bounded child handle.
    fn is_alive(&self, child: &mut ChildHandle) -> bool {
        match &mut child.kind {
            ChildKind::Process(process) => process.try_wait().ok().flatten().is_none(),
            ChildKind::Fake => true,
        }
    }
}

/// Kill a child and remove its one-shot bootstrap endpoint after a failed exchange.
async fn terminate_child_after_bootstrap_failure(child: &mut Child, ipc_path: &Path) {
    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = fs::remove_file(ipc_path);
}

/// A deterministic child spawner used by RSB-2 contract/fake tests.
#[derive(Debug)]
pub struct FakeChildSpawner {
    /// Next deterministic fake process ID.
    next_pid: std::sync::atomic::AtomicU32,
    /// Currently live fake process IDs.
    live: Mutex<BTreeSet<u32>>,
}

impl Default for FakeChildSpawner {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeChildSpawner {
    /// Create an empty deterministic fake spawner.
    pub fn new() -> Self {
        Self {
            next_pid: std::sync::atomic::AtomicU32::new(10_000),
            live: Mutex::new(BTreeSet::new()),
        }
    }

    /// Return the number of fake children currently alive.
    pub fn live_count(&self) -> usize {
        self.live.lock().map(|set| set.len()).unwrap_or_default()
    }
}

impl ChildSpawner for FakeChildSpawner {
    /// Allocate a deterministic fake child without opening a socket or process.
    fn spawn<'a>(&'a self, spec: ChildSpec) -> ChildFuture<'a, ChildHandle> {
        Box::pin(async move {
            let pid = self
                .next_pid
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.live
                .lock()
                .map_err(|_| RelayError::ChildLifecycle {
                    reason: "fake child registry is poisoned",
                })?
                .insert(pid);
            Ok(ChildHandle {
                pid,
                generation: spec.generation,
                data_port: spec.data_port,
                kind: ChildKind::Fake,
            })
        })
    }

    /// Remove one deterministic fake child.
    fn stop<'a>(&'a self, child: &'a mut ChildHandle) -> ChildFuture<'a, ()> {
        Box::pin(async move {
            self.live
                .lock()
                .map_err(|_| RelayError::ChildLifecycle {
                    reason: "fake child registry is poisoned",
                })?
                .remove(&child.pid);
            Ok(())
        })
    }

    /// Check whether the fake process ID remains registered.
    fn is_alive(&self, child: &mut ChildHandle) -> bool {
        self.live
            .lock()
            .map(|set| set.contains(&child.pid))
            .unwrap_or(false)
    }
}

/// A sanitized lease result returned by Manager ensure/heartbeat operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    /// Canonical session name.
    session: SessionName,
    /// Session fingerprint retained only as an opaque value.
    fingerprint: SessionFingerprint,
    /// Manager generation for the current process instance.
    broker_generation: u64,
    /// Session child generation.
    child_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Reserved data port.
    data_port: u16,
    /// Opaque lease token.
    token: LeaseToken,
    /// Absolute epoch-second lease expiry used for persistence-safe comparisons.
    expires_at: u64,
}

impl LeaseGrant {
    /// Return the canonical session name.
    pub fn session(&self) -> &SessionName {
        &self.session
    }

    /// Return the session fingerprint as an opaque typed value.
    pub fn fingerprint(&self) -> SessionFingerprint {
        self.fingerprint
    }

    /// Return the Manager generation.
    pub fn broker_generation(&self) -> u64 {
        self.broker_generation
    }

    /// Return the child generation.
    pub fn child_generation(&self) -> u64 {
        self.child_generation
    }

    /// Return the session configuration generation.
    pub fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// Return the reserved session data port.
    pub fn data_port(&self) -> u16 {
        self.data_port
    }

    /// Return the opaque lease token for the Core data binding.
    pub fn token(&self) -> LeaseToken {
        self.token
    }

    /// Return the epoch-second lease expiry.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// A sanitized session status returned by Manager diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStatusView {
    /// Canonical session name.
    pub session: SessionName,
    /// Opaque session fingerprint retained for Core control responses.
    pub fingerprint: SessionFingerprint,
    /// Session configuration generation.
    pub configuration_generation: u64,
    /// Whether a non-secret fingerprint is present.
    pub fingerprint_present: bool,
    /// Current child generation.
    pub child_generation: u64,
    /// Reserved data port.
    pub data_port: u16,
    /// Number of active leases.
    pub active_leases: usize,
    /// Idle-grace start, when no leases remain.
    pub idle_since: Option<u64>,
}

/// A bounded result from lease expiration and idle child reclamation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    /// Number of leases expired by the operation.
    pub expired_leases: usize,
    /// Session names whose child was stopped after idle grace.
    pub stopped_sessions: Vec<SessionName>,
}

/// One Manager-owned session slot.
struct SessionSlot {
    /// Resolver result and socket identity retained for replacement detection.
    resolved: ResolvedSession,
    /// Persisted session fingerprint.
    fingerprint: SessionFingerprint,
    /// Child generation.
    child_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Allocated data port.
    data_port: u16,
    /// Controlled child process.
    child: ChildHandle,
    /// Active leases indexed by opaque token.
    leases: BTreeMap<LeaseToken, u64>,
    /// Epoch second when the final lease was released or expired.
    idle_since: Option<u64>,
}

/// An OS-level exclusive lock that prevents two Managers sharing one root.
struct ManagerLock {
    /// The locked file retained for the Manager lifetime.
    file: File,
}

impl ManagerLock {
    /// Open and exclusively lock the Manager root lock file.
    fn acquire(path: &Path, expected_uid: u32) -> RelayResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|error| RelayError::io("opening Manager lock", error))?;
        let metadata = file
            .metadata()
            .map_err(|error| RelayError::io("checking Manager lock", error))?;
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(RelayError::Manager {
                reason: "Manager lock owner or permissions are invalid",
            });
        }
        file.try_lock_exclusive().map_err(|_| RelayError::Manager {
            reason: "another Manager instance owns this root",
        })?;
        Ok(Self { file })
    }
}

impl Drop for ManagerLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// The RSB-2 Manager local lifecycle owner.
pub struct Manager {
    /// The exclusive root lock held for this Manager lifetime.
    _lock: ManagerLock,
    /// Validated policy configuration.
    config: ManagerConfig,
    /// Source-aligned Herdr session resolver.
    resolver: HerdrSessionResolver,
    /// Non-secret fingerprint store.
    fingerprints: FingerprintStore,
    /// Atomic state file owner.
    state_store: ManagerStateStore,
    /// Persisted non-secret Manager state.
    state: PersistedManagerState,
    /// Bounded data-port allocation.
    ports: DataPortAllocator,
    /// Controlled child lifecycle implementation.
    child_spawner: Arc<dyn ChildSpawner>,
    /// Active session slots.
    sessions: BTreeMap<SessionName, SessionSlot>,
}

impl fmt::Debug for Manager {
    /// Render bounded counts without paths, fingerprints, tokens, or child command lines.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Manager")
            .field("broker_generation", &self.state.broker_generation)
            .field("session_count", &self.sessions.len())
            .field("reserved_port_count", &self.ports.allocated.len())
            .finish()
    }
}

impl Manager {
    /// Open a production Manager using the configured same-binary child spawner.
    ///
    /// # Arguments
    ///
    /// * `config` - Validated Manager policy.
    /// * `expected_uid` - User owner for Manager and Herdr session files.
    ///
    /// # Returns
    ///
    /// A Manager with a new persisted process generation.
    pub fn open(config: ManagerConfig, expected_uid: u32) -> RelayResult<Self> {
        let child_spawner = Arc::new(ProcessChildSpawner::new(config.child_binary())?);
        Self::with_spawner(config, expected_uid, child_spawner)
    }

    /// Open a Manager with an injected child spawner for deterministic local tests.
    ///
    /// # Arguments
    ///
    /// * `config` - Validated Manager policy.
    /// * `expected_uid` - User owner for Manager and Herdr session files.
    /// * `child_spawner` - Production or fake child lifecycle implementation.
    ///
    /// # Returns
    ///
    /// A Manager with a new persisted process generation.
    pub fn with_spawner(
        config: ManagerConfig,
        expected_uid: u32,
        child_spawner: Arc<dyn ChildSpawner>,
    ) -> RelayResult<Self> {
        config.validate()?;
        ensure_private_directory(config.manager_root(), expected_uid)?;
        ensure_private_directory(&config.manager_root().join("sessions"), expected_uid)?;
        let lock = ManagerLock::acquire(&config.manager_root().join("manager.lock"), expected_uid)?;
        let state_store = ManagerStateStore::new(config.manager_root().join(MANAGER_STATE_FILE));
        let mut state = state_store.load()?;
        if state.broker_generation == 0 {
            state.preferred_broker_port = config.preferred_broker_port();
        }
        state.broker_generation = state
            .broker_generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .unwrap_or(1);
        state_store.save(&state)?;
        let ports = DataPortAllocator::new(config.data_port_start, config.data_port_end)?;
        Ok(Self {
            _lock: lock,
            resolver: HerdrSessionResolver::new(config.herdr_config_root(), expected_uid)?,
            fingerprints: FingerprintStore::new(expected_uid),
            state_store,
            state,
            ports,
            child_spawner,
            sessions: BTreeMap::new(),
            config,
        })
    }

    /// Ensure a session is existing, reachable, fingerprint-bound, and leased.
    ///
    /// # Arguments
    ///
    /// * `raw_session` - Empty or normalized/default/named session input.
    /// * `now` - Current epoch seconds supplied by the owning clock.
    ///
    /// # Returns
    ///
    /// A new opaque lease grant, or a fail-closed readiness error.
    pub async fn ensure(&mut self, raw_session: &str, now: u64) -> RelayResult<LeaseGrant> {
        let session = SessionName::normalize(raw_session)?;
        let resolved = self.resolver.resolve(&session)?;
        self.resolver.verify_reachable(&resolved).await?;
        let fingerprint = self.fingerprints.load_or_create(&resolved)?;
        self.remove_dead_child(&session).await?;

        if let Some(slot) = self.sessions.get_mut(&session) {
            if slot.fingerprint != fingerprint {
                return Err(RelayError::Manager {
                    reason: "session fingerprint changed; explicit rebind is required",
                });
            }
            if slot.resolved.socket_identity() != resolved.socket_identity() {
                return Err(RelayError::SocketIdentity {
                    operation: "checking Herdr Unix socket",
                    reason: "socket identity changed for active session",
                });
            }
            let token = LeaseToken::generate();
            let expires_at = checked_add_seconds(now, self.config.lease_expiry.as_secs())?;
            slot.leases.insert(token, expires_at);
            slot.idle_since = None;
            let grant = lease_grant(
                slot,
                &session,
                token,
                expires_at,
                self.state.broker_generation,
            );
            self.persist_state()?;
            return Ok(grant);
        }

        let expires_at = checked_add_seconds(now, self.config.lease_expiry.as_secs())?;
        let data_port = self.ports.reserve()?;
        let child_generation = match self.next_child_generation() {
            Ok(generation) => generation,
            Err(error) => {
                self.ports.release(data_port);
                return Err(error);
            }
        };
        let token = LeaseToken::generate();
        let config_path = match write_session_relay_config(
            self.config.manager_root(),
            &resolved,
            data_port,
            self.config.preferred_broker_port(),
        ) {
            Ok(path) => path,
            Err(error) => {
                self.ports.release(data_port);
                return Err(error);
            }
        };
        let ipc_path = match config_path.parent() {
            Some(parent) => parent.join(format!(".child-{child_generation}.sock")),
            None => {
                self.ports.release(data_port);
                let _ = fs::remove_file(&config_path);
                return Err(RelayError::Manager {
                    reason: "generated session configuration has no parent",
                });
            }
        };
        let spec = ChildSpec {
            session: session.clone(),
            generation: child_generation,
            data_port,
            parent_pid: std::process::id(),
            ipc_path,
            token,
        };
        let child = match self.child_spawner.spawn(spec).await {
            Ok(child) => child,
            Err(error) => {
                self.ports.release(data_port);
                let _ = fs::remove_file(config_path);
                return Err(error);
            }
        };
        let mut leases = BTreeMap::new();
        leases.insert(token, expires_at);
        let slot = SessionSlot {
            resolved,
            fingerprint,
            child_generation,
            configuration_generation: 1,
            data_port,
            child,
            leases,
            idle_since: None,
        };
        self.sessions.insert(session.clone(), slot);
        if let Err(error) = self.persist_state() {
            if let Some(mut rollback) = self.sessions.remove(&session) {
                self.ports.release(rollback.data_port);
                let _ = self.child_spawner.stop(&mut rollback.child).await;
            }
            let _ = fs::remove_file(config_path);
            return Err(error);
        }
        let slot = self.sessions.get(&session).ok_or(RelayError::Manager {
            reason: "new session slot disappeared",
        })?;
        Ok(lease_grant(
            slot,
            &session,
            token,
            expires_at,
            self.state.broker_generation,
        ))
    }

    /// Renew one lease and return its updated sanitized grant.
    ///
    /// # Arguments
    ///
    /// * `token` - The opaque token issued by `ensure`.
    /// * `now` - Current epoch seconds supplied by the owning clock.
    ///
    /// # Returns
    ///
    /// An updated grant or `InvalidLease` when the token is stale/expired.
    pub fn heartbeat(&mut self, token: LeaseToken, now: u64) -> RelayResult<LeaseGrant> {
        let session = self
            .sessions
            .iter()
            .find_map(|(session, slot)| slot.leases.contains_key(&token).then_some(session.clone()))
            .ok_or(RelayError::InvalidLease)?;
        let (grant, expired) = {
            let slot = self
                .sessions
                .get_mut(&session)
                .ok_or(RelayError::InvalidLease)?;
            let expires_at = *slot.leases.get(&token).ok_or(RelayError::InvalidLease)?;
            if now >= expires_at {
                slot.leases.remove(&token);
                if slot.leases.is_empty() {
                    slot.idle_since = Some(now);
                }
                (None, true)
            } else {
                let new_expiry = checked_add_seconds(now, self.config.lease_expiry.as_secs())?;
                slot.leases.insert(token, new_expiry);
                (
                    Some(lease_grant(
                        slot,
                        &session,
                        token,
                        new_expiry,
                        self.state.broker_generation,
                    )),
                    false,
                )
            }
        };
        self.persist_state()?;
        if expired {
            Err(RelayError::InvalidLease)
        } else {
            grant.ok_or(RelayError::InvalidLease)
        }
    }

    /// Open the validated Herdr Unix stream for one active lease after authority checks.
    ///
    /// # Arguments
    ///
    /// * `token` - The in-memory lease token previously issued by `ensure`.
    /// * `session` - The normalized session bound to the lease.
    /// * `now` - Current epoch seconds used to reject expired leases.
    ///
    /// # Returns
    ///
    /// A validated Unix stream or a redacted lease/socket error. The stream carries opaque bytes;
    /// this method never parses Herdr data.
    // TEST:relay/tests/rsb3_control.rs[broker_control_round_trip_and_hdbd_gate]
    pub async fn open_bound_stream(
        &self,
        token: LeaseToken,
        session: &SessionName,
        now: u64,
    ) -> RelayResult<UnixStream> {
        let slot = self.sessions.get(session).ok_or(RelayError::InvalidLease)?;
        let expires_at = slot
            .leases
            .get(&token)
            .copied()
            .ok_or(RelayError::InvalidLease)?;
        if now >= expires_at {
            return Err(RelayError::InvalidLease);
        }
        let connector = UnixSocketConnector::new(
            &slot.resolved.socket,
            slot.resolved.socket_identity().owner_uid(),
        )?;
        connector
            .connect_checked(slot.resolved.socket_identity())
            .await
    }

    /// Return whether one opaque lease remains active at the supplied epoch second.
    ///
    /// # Arguments
    ///
    /// * `token` - The in-memory lease authority to inspect.
    /// * `now` - Current epoch seconds.
    ///
    /// # Returns
    ///
    /// `true` only while the lease exists and has not expired.
    // TEST:relay/tests/rsb3_control.rs[broker_control_round_trip_and_hdbd_gate]
    pub fn lease_is_active(&self, token: LeaseToken, now: u64) -> bool {
        self.sessions.values().any(|slot| {
            slot.leases
                .get(&token)
                .is_some_and(|expires_at| now < *expires_at)
        })
    }

    /// Release one lease while retaining an idle child through the configured grace period.
    ///
    /// # Arguments
    ///
    /// * `token` - The opaque lease token to release.
    /// * `now` - Current epoch seconds supplied by the owning clock.
    ///
    /// # Returns
    ///
    /// `Ok(())` after release, or `InvalidLease` for an unknown token.
    pub fn release(&mut self, token: LeaseToken, now: u64) -> RelayResult<()> {
        let session = self
            .sessions
            .iter()
            .find_map(|(session, slot)| slot.leases.contains_key(&token).then_some(session.clone()))
            .ok_or(RelayError::InvalidLease)?;
        let slot = self
            .sessions
            .get_mut(&session)
            .ok_or(RelayError::InvalidLease)?;
        slot.leases.remove(&token);
        if slot.leases.is_empty() {
            slot.idle_since = Some(now);
        }
        self.persist_state()
    }

    /// Expire leases and stop children whose idle grace has elapsed.
    ///
    /// # Arguments
    ///
    /// * `now` - Current epoch seconds supplied by the owning clock.
    ///
    /// # Returns
    ///
    /// Counts and sanitized session names for the work performed.
    pub async fn reap(&mut self, now: u64) -> RelayResult<ReapReport> {
        let mut report = ReapReport::default();
        for slot in self.sessions.values_mut() {
            let expired: Vec<LeaseToken> = slot
                .leases
                .iter()
                .filter_map(|(token, expires_at)| (*expires_at <= now).then_some(*token))
                .collect();
            let expired_count = expired.len();
            report.expired_leases += expired_count;
            for token in expired {
                slot.leases.remove(&token);
            }
            if expired_count > 0 && slot.leases.is_empty() && slot.idle_since.is_none() {
                slot.idle_since = Some(now);
            }
        }
        let idle_sessions: Vec<SessionName> = self
            .sessions
            .iter()
            .filter_map(|(session, slot)| {
                slot.idle_since
                    .and_then(|idle_since| {
                        checked_add_seconds(idle_since, self.config.idle_grace.as_secs()).ok()
                    })
                    .filter(|deadline| now >= *deadline)
                    .map(|_| session.clone())
            })
            .collect();
        for session in idle_sessions {
            if let Some(mut slot) = self.sessions.remove(&session) {
                self.ports.release(slot.data_port);
                self.child_spawner.stop(&mut slot.child).await?;
                report.stopped_sessions.push(session);
            }
        }
        if report.expired_leases > 0 || !report.stopped_sessions.is_empty() {
            self.persist_state()?;
        }
        Ok(report)
    }

    /// Return sanitized status for all active session slots.
    pub fn status(&self) -> Vec<SessionStatusView> {
        self.sessions
            .iter()
            .map(|(session, slot)| SessionStatusView {
                session: session.clone(),
                fingerprint: slot.fingerprint,
                configuration_generation: slot.configuration_generation,
                fingerprint_present: true,
                child_generation: slot.child_generation,
                data_port: slot.data_port,
                active_leases: slot.leases.len(),
                idle_since: slot.idle_since,
            })
            .collect()
    }

    /// Render the user-level LaunchAgent plist without secrets or runtime state.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Manager TOML path to pass to the controlled binary.
    ///
    /// # Returns
    ///
    /// A bounded XML plist template for explicit user installation.
    pub fn launch_agent_plist(&self, config_path: &Path) -> RelayResult<String> {
        validate_absolute_path("manager_config", config_path)?;
        render_launch_agent(&self.config.child_binary, config_path)
    }

    /// Return the current Manager generation.
    pub fn broker_generation(&self) -> u64 {
        self.state.broker_generation
    }

    /// Return the validated Manager configuration.
    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Increment and persist the next child generation without exposing state externally.
    fn next_child_generation(&mut self) -> RelayResult<u64> {
        let generation = self.state.next_child_generation;
        self.state.next_child_generation = self
            .state
            .next_child_generation
            .checked_add(1)
            .filter(|value| *value != 0)
            .unwrap_or(1);
        self.persist_state()?;
        Ok(generation)
    }

    /// Persist only non-secret Manager state.
    fn persist_state(&self) -> RelayResult<()> {
        self.state_store.save(&self.state)
    }

    /// Remove an externally dead child before reusing its session slot.
    async fn remove_dead_child(&mut self, session: &SessionName) -> RelayResult<()> {
        let dead = self
            .sessions
            .get_mut(session)
            .map(|slot| !self.child_spawner.is_alive(&mut slot.child))
            .unwrap_or(false);
        if !dead {
            return Ok(());
        }
        if let Some(mut slot) = self.sessions.remove(session) {
            self.ports.release(slot.data_port);
            self.child_spawner.stop(&mut slot.child).await?;
        }
        Ok(())
    }
}

/// Persistent Manager state containing no lease tokens or session fingerprints.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedManagerState {
    /// Monotonic Manager process generation.
    broker_generation: u64,
    /// Next child generation.
    next_child_generation: u64,
    /// Last preferred Broker discovery port.
    preferred_broker_port: u16,
}

impl Default for PersistedManagerState {
    fn default() -> Self {
        Self {
            broker_generation: 0,
            next_child_generation: 1,
            preferred_broker_port: BROKER_DISCOVERY_PORT_BASE,
        }
    }
}

/// Atomic JSON state file owner.
struct ManagerStateStore {
    /// State file path.
    path: PathBuf,
}

impl ManagerStateStore {
    /// Create a state store for one validated Manager root.
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load state or return a fresh default when the file is absent.
    fn load(&self) -> RelayResult<PersistedManagerState> {
        let state = match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| RelayError::Manager {
                reason: "manager state JSON is invalid",
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PersistedManagerState::default())
            }
            Err(error) => Err(RelayError::io("reading manager state", error)),
        }?;
        if !(BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST)
            .contains(&state.preferred_broker_port)
            || state.next_child_generation == 0
        {
            return Err(RelayError::Manager {
                reason: "manager state is outside the frozen policy",
            });
        }
        Ok(state)
    }

    /// Atomically write bounded non-secret state with mode 0600.
    fn save(&self, state: &PersistedManagerState) -> RelayResult<()> {
        let bytes = serde_json::to_vec_pretty(state).map_err(|_| RelayError::Manager {
            reason: "manager state could not be encoded",
        })?;
        atomic_write(&self.path, &bytes, 0o600)
    }
}

/// Encode a generated relay.toml using structured serialization and no runtime secrets.
fn write_session_relay_config(
    manager_root: &Path,
    session: &ResolvedSession,
    data_port: u16,
    preferred_broker_port: u16,
) -> RelayResult<PathBuf> {
    let path = session.relay_config_path(manager_root);
    let parent = path.parent().ok_or(RelayError::Manager {
        reason: "session configuration has no parent",
    })?;
    ensure_private_directory(parent, session.socket_identity().owner_uid())?;
    #[derive(Serialize)]
    struct GeneratedRelay<'a> {
        herdr_socket: &'a str,
    }
    #[derive(Serialize)]
    struct GeneratedListener<'a> {
        enabled: bool,
        tls: bool,
        bind_address: &'a str,
        allowed_sources: [&'a str; 1],
    }
    #[derive(Serialize)]
    struct GeneratedNetwork<'a> {
        port_base: u16,
        port_attempts: u8,
        tailscale: GeneratedListener<'a>,
        lan: GeneratedListener<'a>,
        public: GeneratedListener<'a>,
    }
    #[derive(Serialize)]
    struct GeneratedLimits {
        max_clients: u16,
        max_clients_per_listener: u16,
        max_handshakes: u16,
        handshake_timeout_secs: u64,
        probe_timeout_secs: u64,
        idle_timeout_secs: u64,
        buffer_bytes: usize,
        max_diagnostic_bytes: usize,
    }
    #[derive(Serialize)]
    struct GeneratedConfig<'a> {
        relay: GeneratedRelay<'a>,
        network: GeneratedNetwork<'a>,
        limits: GeneratedLimits,
    }
    let socket = session
        .socket
        .to_str()
        .ok_or(RelayError::InvalidConfiguration {
            field: "relay.herdr_socket",
            reason: "resolved socket path must be UTF-8",
        })?;
    let listener = |enabled: bool, tls: bool| GeneratedListener {
        enabled,
        tls,
        bind_address: "127.0.0.1",
        allowed_sources: ["127.0.0.1"],
    };
    let generated = GeneratedConfig {
        relay: GeneratedRelay {
            herdr_socket: socket,
        },
        network: GeneratedNetwork {
            port_base: BROKER_DISCOVERY_PORT_BASE,
            port_attempts: BROKER_DISCOVERY_PORT_ATTEMPTS as u8,
            tailscale: listener(false, false),
            lan: listener(false, true),
            public: listener(false, true),
        },
        limits: GeneratedLimits {
            max_clients: 64,
            max_clients_per_listener: 32,
            max_handshakes: 16,
            handshake_timeout_secs: 5,
            probe_timeout_secs: 2,
            idle_timeout_secs: V1_IDLE_TIMEOUT_SECS,
            buffer_bytes: V1_BUFFER_BYTES,
            max_diagnostic_bytes: 4096,
        },
    };
    let mut output = String::from(
        "# Generated by herdogrelay Manager. Do not edit; session ownership is Manager-controlled.\n",
    );
    output.push_str(&format!("# manager_data_port = {data_port}\n"));
    output.push_str(&format!(
        "# manager_broker_port = {preferred_broker_port}\n\n"
    ));
    output.push_str(
        &toml::to_string_pretty(&generated).map_err(|_| RelayError::Manager {
            reason: "session relay configuration could not be encoded",
        })?,
    );
    atomic_write(&path, output.as_bytes(), 0o600)?;
    Ok(path)
}

/// Build a sanitized grant from one active session slot.
fn lease_grant(
    slot: &SessionSlot,
    session: &SessionName,
    token: LeaseToken,
    expires_at: u64,
    broker_generation: u64,
) -> LeaseGrant {
    LeaseGrant {
        session: session.clone(),
        fingerprint: slot.fingerprint,
        broker_generation,
        child_generation: slot.child_generation,
        configuration_generation: slot.configuration_generation,
        data_port: slot.data_port,
        token,
        expires_at,
    }
}

/// Render a fixed user-level LaunchAgent plist with XML-escaped non-secret paths.
fn render_launch_agent(binary: &Path, config_path: &Path) -> RelayResult<String> {
    let binary = xml_escape(&binary.to_string_lossy())?;
    let config = xml_escape(&config_path.to_string_lossy())?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{LAUNCH_AGENT_LABEL}</string>\n  <key>ProgramArguments</key>\n  <array><string>{binary}</string><string>manager</string><string>--config</string><string>{config}</string></array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict>\n</plist>\n"
    ))
}

/// Run the controlled child mode after validating and acknowledging Manager bootstrap IPC.
pub async fn run_relay_child(
    ipc_path: &Path,
    session: &str,
    generation: u64,
    data_port: u16,
    parent_pid: u32,
) -> RelayResult<()> {
    let expected_session = SessionName::normalize(session)?;
    validate_data_port(data_port)?;
    validate_ipc_path(ipc_path)?;
    let mut stream = timeout(
        Duration::from_secs(CHILD_BOOTSTRAP_TIMEOUT_SECS),
        UnixStream::connect(ipc_path),
    )
    .await
    .map_err(|_| RelayError::ChildLifecycle {
        reason: "child could not connect to Manager bootstrap IPC",
    })?
    .map_err(|error| RelayError::io("connecting child bootstrap IPC", error))?;
    receive_child_bootstrap(
        &mut stream,
        &expected_session,
        generation,
        data_port,
        Duration::from_secs(CHILD_BOOTSTRAP_TIMEOUT_SECS),
    )
    .await?;
    wait_for_child_shutdown(parent_pid).await;
    Ok(())
}

/// Wait for user-level child termination without accepting arbitrary commands.
async fn wait_for_child_shutdown(parent_pid: u32) {
    let parent_exit = wait_for_parent_death(parent_pid, Duration::from_secs(1));
    tokio::select! {
        _ = parent_exit => {}
        _ = child_signal_shutdown() => {}
    }
}

/// Poll for parent process termination at a caller-selected interval.
///
/// # Arguments
///
/// * `parent_pid` - The Manager process identifier passed during child bootstrap.
/// * `poll_interval` - The bounded delay between liveness checks.
///
/// # Returns
///
/// Completes once the parent no longer exists according to the OS liveness probe.
async fn wait_for_parent_death(parent_pid: u32, poll_interval: Duration) {
    loop {
        time::sleep(poll_interval).await;
        if !parent_process_alive(parent_pid).await {
            break;
        }
    }
}

/// Wait for an explicit child termination signal.
async fn child_signal_shutdown() {
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Check parent liveness without accepting arbitrary commands or paths.
async fn parent_process_alive(parent_pid: u32) -> bool {
    Command::new("/bin/kill")
        .arg("-0")
        .arg(parent_pid.to_string())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Bounded child bootstrap authority frame.
struct ChildBootstrap {
    /// Token delivered only over protected IPC.
    token: LeaseToken,
    /// Child generation.
    generation: u64,
    /// Data port assigned by Manager.
    data_port: u16,
    /// Canonical session.
    session: SessionName,
}

impl fmt::Debug for ChildBootstrap {
    /// Render bootstrap metadata without exposing the token.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildBootstrap")
            .field("generation", &self.generation)
            .field("data_port", &self.data_port)
            .field("session", &self.session)
            .field("token", &self.token)
            .finish()
    }
}

impl ChildBootstrap {
    /// Encode one complete bootstrap frame without writing it to disk or argv.
    fn encode(spec: &ChildSpec) -> RelayResult<Vec<u8>> {
        let session = spec.session.as_str().as_bytes();
        let total = 4 + 2 + 32 + 8 + 2 + 1 + session.len();
        if session.len() > 64 || total > MAX_CHILD_FRAME_BYTES {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap session is too large",
            });
        }
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&CHILD_BOOTSTRAP_MAGIC);
        frame.extend_from_slice(&CHILD_BOOTSTRAP_VERSION.to_be_bytes());
        frame.extend_from_slice(&spec.token.0);
        frame.extend_from_slice(&spec.generation.to_be_bytes());
        frame.extend_from_slice(&spec.data_port.to_be_bytes());
        frame.push(session.len() as u8);
        frame.extend_from_slice(session);
        Ok(frame)
    }

    /// Decode and validate one bounded child bootstrap frame.
    fn decode(input: &[u8]) -> RelayResult<Self> {
        if input.len() < 4 + 2 + 32 + 8 + 2 + 1
            || input.len() > MAX_CHILD_FRAME_BYTES
            || input[..4] != CHILD_BOOTSTRAP_MAGIC
            || input[4..6] != CHILD_BOOTSTRAP_VERSION.to_be_bytes()
        {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap frame is invalid",
            });
        }
        let token =
            LeaseToken(
                input[6..38]
                    .try_into()
                    .map_err(|_| RelayError::ChildLifecycle {
                        reason: "child bootstrap token is invalid",
                    })?,
            );
        let generation = u64::from_be_bytes(input[38..46].try_into().map_err(|_| {
            RelayError::ChildLifecycle {
                reason: "child bootstrap generation is invalid",
            }
        })?);
        let data_port = u16::from_be_bytes(input[46..48].try_into().map_err(|_| {
            RelayError::ChildLifecycle {
                reason: "child bootstrap data port is invalid",
            }
        })?);
        validate_data_port(data_port)?;
        let session_len = input[48] as usize;
        let end = 49 + session_len;
        if end != input.len() {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap session length is invalid",
            });
        }
        let session_text =
            std::str::from_utf8(&input[49..end]).map_err(|_| RelayError::ChildLifecycle {
                reason: "child bootstrap session is not UTF-8",
            })?;
        Ok(Self {
            token,
            generation,
            data_port,
            session: SessionName::normalize(session_text)?,
        })
    }
}

/// Complete the bounded Manager-side bootstrap write and acknowledgement read.
///
/// # Arguments
///
/// * `stream` - The accepted protected Unix bootstrap stream.
/// * `frame` - The already-encoded bounded bootstrap frame.
/// * `deadline` - The maximum duration for both write and acknowledgement.
///
/// # Returns
///
/// `Ok(())` after a valid acknowledgement, or a sanitized lifecycle error.
async fn exchange_child_bootstrap(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Duration,
) -> RelayResult<()> {
    timeout(deadline, async {
        stream
            .write_all(frame)
            .await
            .map_err(|error| RelayError::io("sending child bootstrap", error))?;
        let mut ack = [0_u8; CHILD_ACK.len()];
        stream
            .read_exact(&mut ack)
            .await
            .map_err(|error| RelayError::io("reading child bootstrap acknowledgement", error))?;
        if ack != CHILD_ACK {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap acknowledgement is invalid",
            });
        }
        Ok::<(), RelayError>(())
    })
    .await
    .map_err(|_| RelayError::ChildLifecycle {
        reason: "child bootstrap exchange timed out",
    })?
}

/// Validate and acknowledge one bounded bootstrap frame on the child side.
///
/// # Arguments
///
/// * `stream` - The connected protected Unix bootstrap stream.
/// * `expected_session` - The normalized session encoded in the child command.
/// * `generation` - The expected child generation.
/// * `data_port` - The expected bounded session data port.
/// * `deadline` - The maximum duration for frame read and acknowledgement.
///
/// # Returns
///
/// `Ok(())` after authority validation and acknowledgement, or a sanitized lifecycle error.
async fn receive_child_bootstrap(
    stream: &mut UnixStream,
    expected_session: &SessionName,
    generation: u64,
    data_port: u16,
    deadline: Duration,
) -> RelayResult<()> {
    timeout(deadline, async {
        let mut prefix = [0_u8; 4 + 2 + 32 + 8 + 2 + 1];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|error| RelayError::io("reading child bootstrap", error))?;
        let session_len = *prefix.last().ok_or(RelayError::ChildLifecycle {
            reason: "child bootstrap prefix is invalid",
        })? as usize;
        let total = prefix.len() + session_len;
        if total > MAX_CHILD_FRAME_BYTES {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap exceeds its bound",
            });
        }
        let mut frame = prefix.to_vec();
        frame.resize(total, 0);
        stream
            .read_exact(&mut frame[prefix.len()..])
            .await
            .map_err(|error| RelayError::io("reading child bootstrap session", error))?;
        let bootstrap = ChildBootstrap::decode(&frame)?;
        if bootstrap.session != *expected_session
            || bootstrap.generation != generation
            || bootstrap.data_port != data_port
        {
            return Err(RelayError::ChildLifecycle {
                reason: "child bootstrap authority does not match command",
            });
        }
        stream
            .write_all(&CHILD_ACK)
            .await
            .map_err(|error| RelayError::io("acknowledging child bootstrap", error))?;
        Ok::<(), RelayError>(())
    })
    .await
    .map_err(|_| RelayError::ChildLifecycle {
        reason: "child bootstrap exchange timed out",
    })?
}

/// Validate a fixed RSB data port.
fn validate_data_port(port: u16) -> RelayResult<()> {
    if !(BROKER_DATA_PORT_BASE..=BROKER_DATA_PORT_LAST).contains(&port) {
        return Err(RelayError::InvalidConfiguration {
            field: "data_port",
            reason: "must remain in 18753..18852",
        });
    }
    Ok(())
}

/// Validate a protected Unix IPC path without exposing it in errors.
fn validate_ipc_path(path: &Path) -> RelayResult<()> {
    validate_absolute_path("child_ipc", path)?;
    let parent = path.parent().ok_or(RelayError::ChildLifecycle {
        reason: "child bootstrap IPC has no parent",
    })?;
    validate_existing_path_components(parent)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| RelayError::ChildLifecycle {
        reason: "child bootstrap IPC parent is unavailable",
    })?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o700 != 0o700
    {
        return Err(RelayError::ChildLifecycle {
            reason: "child bootstrap IPC parent boundary is invalid",
        });
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o600)
    {
        return Err(RelayError::ChildLifecycle {
            reason: "child bootstrap IPC boundary is invalid",
        });
    }
    Ok(())
}

/// Resolve an explicit path or the supplied `auto` fallback.
fn resolve_path(
    value: PathBuf,
    fallback: Option<PathBuf>,
    field: &'static str,
) -> RelayResult<PathBuf> {
    let path = if value == Path::new("auto") {
        fallback.ok_or(RelayError::InvalidConfiguration {
            field,
            reason: "auto path cannot be resolved",
        })?
    } else {
        value
    };
    validate_absolute_path(field, &path)?;
    Ok(path)
}

/// Return the Herdr application directory selected by the current build profile.
fn herdr_app_dir() -> &'static str {
    if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    }
}

/// Return a safe default path for Manager state.
fn default_manager_root() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".config/herdr-dog/manager"))
}

/// Return the Herdr configuration root from XDG or HOME.
fn default_herdr_config_root() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })
}

/// Convert a path-like TOML default into the auto sentinel.
fn auto_path() -> PathBuf {
    PathBuf::from("auto")
}

/// Return the fixed default preferred Broker port.
fn default_preferred_broker_port() -> u16 {
    BROKER_DISCOVERY_PORT_BASE
}

/// Return the fixed Broker candidate count.
fn default_broker_port_attempts() -> u16 {
    BROKER_DISCOVERY_PORT_ATTEMPTS
}

/// Return the fixed first data port.
fn default_data_port_start() -> u16 {
    BROKER_DATA_PORT_BASE
}

/// Return the fixed last data port.
fn default_data_port_end() -> u16 {
    BROKER_DATA_PORT_LAST
}

/// Return the fixed heartbeat interval.
fn default_heartbeat_secs() -> u64 {
    MANAGER_HEARTBEAT_INTERVAL_SECS
}

/// Return the fixed lease expiry interval.
fn default_lease_expiry_secs() -> u64 {
    MANAGER_LEASE_EXPIRY_SECS
}

/// Return the fixed idle grace interval.
fn default_idle_grace_secs() -> u64 {
    MANAGER_IDLE_GRACE_SECS
}

/// Validate existing path components without accepting symlink traversal.
fn validate_existing_path_components(path: &Path) -> RelayResult<()> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if component == std::path::Component::RootDir {
            continue;
        }
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RelayError::SocketIdentity {
                    operation: "checking Manager path",
                    reason: "path contains a symlink component",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(RelayError::io("checking Manager path", error)),
        }
    }
    Ok(())
}

/// Create or validate a private user-owned directory.
fn ensure_private_directory(path: &Path, expected_uid: u32) -> RelayResult<()> {
    validate_absolute_path("manager_directory", path)?;
    validate_existing_path_components(path)?;
    let existed = fs::symlink_metadata(path).is_ok();
    fs::create_dir_all(path)
        .map_err(|error| RelayError::io("creating Manager directory", error))?;
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| RelayError::io("protecting Manager directory", error))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RelayError::io("checking Manager directory", error))?;
    let mode = metadata.permissions().mode();
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
    {
        return Err(RelayError::SocketIdentity {
            operation: "checking Manager directory",
            reason: "directory owner, type, or permissions are invalid",
        });
    }
    Ok(())
}

/// Atomically create a private file and fail if a concurrent creator won first.
fn create_private_file(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Atomically replace one bounded private file.
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> RelayResult<()> {
    let parent = path.parent().ok_or(RelayError::Manager {
        reason: "atomic file has no parent",
    })?;
    let file_name = path.file_name().ok_or(RelayError::Manager {
        reason: "atomic file has no name",
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_name = format!(
        ".{}.tmp-{}-{nonce}",
        file_name.to_string_lossy(),
        std::process::id()
    );
    let temp = parent.join(temp_name);
    let result = (|| -> RelayResult<()> {
        create_private_file(&temp, bytes, mode)
            .map_err(|error| RelayError::io("writing atomic Manager file", error))?;
        fs::rename(&temp, path)
            .map_err(|error| RelayError::io("installing atomic Manager file", error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| RelayError::io("protecting Manager file", error))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Encode a fingerprint as fixed-width lowercase hexadecimal.
fn encode_fingerprint(fingerprint: SessionFingerprint) -> Vec<u8> {
    let mut output = Vec::with_capacity(FINGERPRINT_TEXT_BYTES);
    for byte in fingerprint.0 {
        output.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    output
}

/// Decode the fixed-width lowercase hexadecimal fingerprint representation.
fn decode_fingerprint(bytes: &[u8]) -> RelayResult<SessionFingerprint> {
    if bytes.len() != FINGERPRINT_TEXT_BYTES || !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RelayError::InvalidFingerprint);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_value(pair[0]).ok_or(RelayError::InvalidFingerprint)?;
        let low = hex_value(pair[1]).ok_or(RelayError::InvalidFingerprint)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(SessionFingerprint(decoded))
}

/// Decode one ASCII hexadecimal digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Return an overflow-checked epoch-second deadline.
fn checked_add_seconds(now: u64, seconds: u64) -> RelayResult<u64> {
    now.checked_add(seconds).ok_or(RelayError::Manager {
        reason: "lease deadline overflowed",
    })
}

/// Escape a bounded XML text value.
fn xml_escape(value: &str) -> RelayResult<String> {
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(RelayError::InvalidConfiguration {
            field: "manager_launch_agent_path",
            reason: "path contains XML control characters",
        });
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

/// Return current epoch seconds for CLI lifecycle commands.
pub fn epoch_seconds() -> RelayResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RelayError::Manager {
            reason: "system clock precedes Unix epoch",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    fn test_root(label: &str) -> PathBuf {
        let root = fs::canonicalize("/tmp")
            .expect("canonicalize temporary directory")
            .join(format!(
                "hdm-{label}-{}-{}",
                std::process::id(),
                epoch_seconds().expect("clock")
            ));
        fs::create_dir_all(&root).expect("create test root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        root
    }

    fn test_config(root: &Path) -> ManagerConfig {
        ManagerConfig {
            manager_root: root.join("manager"),
            herdr_config_root: root.join("config"),
            child_binary: PathBuf::from("/bin/true"),
            preferred_broker_port: BROKER_DISCOVERY_PORT_BASE,
            broker_port_attempts: BROKER_DISCOVERY_PORT_ATTEMPTS,
            data_port_start: BROKER_DATA_PORT_BASE,
            data_port_end: BROKER_DATA_PORT_LAST,
            heartbeat_interval: Duration::from_secs(MANAGER_HEARTBEAT_INTERVAL_SECS),
            lease_expiry: Duration::from_secs(MANAGER_LEASE_EXPIRY_SECS),
            idle_grace: Duration::from_secs(MANAGER_IDLE_GRACE_SECS),
        }
    }

    async fn test_manager(label: &str) -> (Manager, Arc<FakeChildSpawner>, UnixListener, PathBuf) {
        let root = test_root(label);
        let config_root = root.join("config").join(herdr_app_dir());
        fs::create_dir_all(&config_root).expect("create Herdr root");
        fs::set_permissions(&config_root, fs::Permissions::from_mode(0o700))
            .expect("private Herdr root");
        let socket = config_root.join("herdr.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake Herdr socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .expect("private Herdr socket");
        let uid = fs::symlink_metadata(&socket)
            .expect("socket metadata")
            .uid();
        let fake = Arc::new(FakeChildSpawner::new());
        let manager = Manager::with_spawner(
            test_config(&root),
            uid,
            fake.clone() as Arc<dyn ChildSpawner>,
        )
        .expect("open test manager");
        (manager, fake, listener, root)
    }

    /// Child spawner that fails before creating a process for rollback tests.
    #[derive(Debug)]
    struct FailingChildSpawner;

    impl ChildSpawner for FailingChildSpawner {
        /// Return a deterministic bootstrap failure.
        fn spawn<'a>(&'a self, _spec: ChildSpec) -> ChildFuture<'a, ChildHandle> {
            Box::pin(async {
                Err(RelayError::ChildLifecycle {
                    reason: "test child spawn failure",
                })
            })
        }

        /// Accept cleanup calls without owning a process.
        fn stop<'a>(&'a self, _child: &'a mut ChildHandle) -> ChildFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        /// Report that this fake never owns a live child.
        fn is_alive(&self, _child: &mut ChildHandle) -> bool {
            false
        }
    }

    /// Build a bounded bootstrap frame input for lifecycle contract tests.
    fn bootstrap_test_spec() -> ChildSpec {
        ChildSpec {
            session: SessionName::normalize("work").expect("session"),
            generation: 7,
            data_port: BROKER_DATA_PORT_BASE,
            ipc_path: PathBuf::from("/tmp/child.sock"),
            parent_pid: 42,
            token: LeaseToken([9; 32]),
        }
    }

    // TEST:relay/src/manager.rs[tests::session_normalization_is_source_aligned]
    #[test]
    fn session_normalization_is_source_aligned() {
        assert_eq!(
            SessionName::normalize("").expect("default").as_str(),
            "default"
        );
        assert!(SessionName::normalize("work_1").is_ok());
        assert!(SessionName::normalize("../work").is_err());
        assert!(SessionName::normalize("中文").is_err());
        assert!(SessionName::normalize(".").is_err());
    }

    // TEST:relay/src/manager.rs[tests::default_manager_template_is_valid]
    #[test]
    fn default_manager_template_is_valid() {
        let config = ManagerConfig::from_toml_str(DEFAULT_MANAGER_CONFIG_TOML)
            .expect("default Manager template");
        assert_eq!(
            config.data_port_range(),
            (BROKER_DATA_PORT_BASE, BROKER_DATA_PORT_LAST)
        );
        assert_eq!(config.heartbeat_interval(), Duration::from_secs(30));
        assert_eq!(config.lease_expiry(), Duration::from_secs(90));
        assert_eq!(config.idle_grace(), Duration::from_secs(300));
    }

    // TEST:relay/src/manager.rs[tests::manager_configuration_rejects_widened_ranges]
    #[test]
    fn manager_configuration_rejects_widened_ranges() {
        let root = test_root("config");
        let mut config = test_config(&root);
        config.data_port_end += 1;
        assert!(config.validate().is_err());
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::fingerprint_is_private_and_redacted]
    #[tokio::test(flavor = "current_thread")]
    async fn fingerprint_is_private_and_redacted() {
        let (manager, _, listener, root) = test_manager("fingerprint").await;
        let session = SessionName::normalize("").expect("default");
        let resolved = manager.resolver.resolve(&session).expect("resolve");
        let fingerprint = manager
            .fingerprints
            .load_or_create(&resolved)
            .expect("fingerprint");
        assert!(!format!("{fingerprint:?}").contains("00"));
        let metadata = fs::symlink_metadata(resolved.fingerprint_path()).expect("fingerprint file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::ensure_shares_child_and_port_across_leases]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_shares_child_and_port_across_leases() {
        let (mut manager, fake, listener, root) = test_manager("leases").await;
        let first = manager.ensure("", 100).await.expect("first ensure");
        let second = manager.ensure("default", 110).await.expect("second ensure");
        assert_eq!(first.data_port(), second.data_port());
        assert_ne!(first.token(), second.token());
        assert_eq!(fake.live_count(), 1);
        assert_eq!(manager.status()[0].active_leases, 2);
        manager.release(first.token(), 120).expect("release first");
        assert_eq!(manager.status()[0].active_leases, 1);
        manager
            .release(second.token(), 130)
            .expect("release second");
        let report = manager.reap(429).await.expect("before grace");
        assert!(report.stopped_sessions.is_empty());
        let report = manager.reap(430).await.expect("after grace");
        assert_eq!(
            report.stopped_sessions,
            vec![SessionName::normalize("default").expect("name")]
        );
        assert_eq!(fake.live_count(), 0);
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::ensure_rejects_changed_fingerprint]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_rejects_changed_fingerprint() {
        let (mut manager, _, listener, root) = test_manager("fingerprint-mismatch").await;
        manager
            .ensure("default", 100)
            .await
            .expect("initial ensure");
        let session = SessionName::normalize("default").expect("session");
        let resolved = manager.resolver.resolve(&session).expect("resolve");
        fs::write(
            resolved.fingerprint_path(),
            "1".repeat(FINGERPRINT_TEXT_BYTES),
        )
        .expect("replace fingerprint");
        assert!(matches!(
            manager.ensure("default", 110).await,
            Err(RelayError::Manager { .. })
        ));
        drop(manager);
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::ensure_rejects_changed_socket_identity]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_rejects_changed_socket_identity() {
        let (mut manager, _, listener, root) = test_manager("socket-identity").await;
        manager
            .ensure("default", 100)
            .await
            .expect("initial ensure");
        let socket = root.join("config").join(herdr_app_dir()).join("herdr.sock");
        drop(listener);
        fs::remove_file(&socket).expect("remove original socket");
        let replacement = UnixListener::bind(&socket).expect("bind replacement socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .expect("protect replacement socket");
        assert!(matches!(
            manager.ensure("default", 110).await,
            Err(RelayError::SocketIdentity { .. })
        ));
        drop(manager);
        drop(replacement);
        fs::remove_file(socket).expect("remove replacement socket");
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::ensure_rejects_unreachable_socket]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_rejects_unreachable_socket() {
        let (mut manager, _, listener, root) = test_manager("unreachable").await;
        let socket = root.join("config").join(herdr_app_dir()).join("herdr.sock");
        drop(listener);
        fs::remove_file(&socket).expect("remove socket");
        assert!(matches!(
            manager.ensure("default", 100).await,
            Err(RelayError::UpstreamUnavailable)
        ));
        drop(manager);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::ensure_spawn_failure_rolls_back_port_and_config]
    #[tokio::test(flavor = "current_thread")]
    async fn ensure_spawn_failure_rolls_back_port_and_config() {
        let root = test_root("spawn-rollback");
        let config_root = root.join("config").join(herdr_app_dir());
        fs::create_dir_all(&config_root).expect("create Herdr root");
        fs::set_permissions(&config_root, fs::Permissions::from_mode(0o700))
            .expect("private Herdr root");
        let socket = config_root.join("herdr.sock");
        let listener = UnixListener::bind(&socket).expect("bind fake Herdr socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .expect("private Herdr socket");
        let uid = fs::symlink_metadata(&socket)
            .expect("socket metadata")
            .uid();
        let mut manager =
            Manager::with_spawner(test_config(&root), uid, Arc::new(FailingChildSpawner))
                .expect("open test manager");
        assert!(matches!(
            manager.ensure("default", 100).await,
            Err(RelayError::ChildLifecycle { .. })
        ));
        let generated = root
            .join("manager")
            .join("sessions")
            .join("default")
            .join(SESSION_RELAY_CONFIG_FILE);
        assert!(!generated.exists());
        assert_eq!(
            manager.ports.reserve().expect("released port"),
            BROKER_DATA_PORT_BASE
        );
        manager.ports.release(BROKER_DATA_PORT_BASE);
        drop(manager);
        drop(listener);
        fs::remove_file(socket).expect("remove socket");
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::expired_lease_cannot_heartbeat]
    #[tokio::test(flavor = "current_thread")]
    async fn expired_lease_cannot_heartbeat() {
        let (mut manager, _, listener, root) = test_manager("expiry").await;
        let grant = manager.ensure("default", 100).await.expect("ensure");
        assert!(matches!(
            manager.heartbeat(grant.token(), 190),
            Err(RelayError::InvalidLease)
        ));
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::multiple_sessions_have_independent_slots]
    #[tokio::test(flavor = "current_thread")]
    async fn multiple_sessions_have_independent_slots() {
        let root = test_root("multi");
        let herdr_root = root.join("config").join(herdr_app_dir());
        let work_root = herdr_root.join("sessions").join("work");
        fs::create_dir_all(&work_root).expect("create named session");
        fs::set_permissions(&herdr_root, fs::Permissions::from_mode(0o700)).expect("default mode");
        fs::set_permissions(
            work_root.parent().expect("sessions parent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("sessions mode");
        fs::set_permissions(&work_root, fs::Permissions::from_mode(0o700)).expect("work mode");
        let default_socket = herdr_root.join("herdr.sock");
        let work_socket = work_root.join("herdr.sock");
        let default_listener = UnixListener::bind(&default_socket).expect("default socket");
        let work_listener = UnixListener::bind(&work_socket).expect("work socket");
        fs::set_permissions(&default_socket, fs::Permissions::from_mode(0o600))
            .expect("default socket mode");
        fs::set_permissions(&work_socket, fs::Permissions::from_mode(0o600))
            .expect("work socket mode");
        let uid = fs::symlink_metadata(&default_socket)
            .expect("socket metadata")
            .uid();
        let fake = Arc::new(FakeChildSpawner::new());
        let mut manager = Manager::with_spawner(
            test_config(&root),
            uid,
            fake.clone() as Arc<dyn ChildSpawner>,
        )
        .expect("open manager");
        let default_grant = manager
            .ensure("default", 100)
            .await
            .expect("default ensure");
        let work_grant = manager.ensure("work", 100).await.expect("work ensure");
        assert_ne!(default_grant.data_port(), work_grant.data_port());
        assert_eq!(manager.status().len(), 2);
        manager
            .release(default_grant.token(), 130)
            .expect("release default");
        manager
            .release(work_grant.token(), 130)
            .expect("release work");
        let report = manager.reap(430).await.expect("reap both sessions");
        assert_eq!(report.stopped_sessions.len(), 2);
        assert_eq!(fake.live_count(), 0);
        drop(default_listener);
        drop(work_listener);
        fs::remove_file(default_socket).expect("remove default socket");
        fs::remove_file(work_socket).expect("remove work socket");
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::manager_lock_rejects_concurrent_and_reopens]
    #[tokio::test(flavor = "current_thread")]
    async fn manager_lock_rejects_concurrent_and_reopens() {
        let (manager, _, listener, root) = test_manager("lock").await;
        let first_generation = manager.broker_generation();
        let uid =
            fs::symlink_metadata(root.join("config").join(herdr_app_dir()).join("herdr.sock"))
                .expect("socket metadata")
                .uid();
        let second =
            Manager::with_spawner(test_config(&root), uid, Arc::new(FakeChildSpawner::new()));
        assert!(matches!(second, Err(RelayError::Manager { .. })));
        drop(manager);
        let reopened =
            Manager::with_spawner(test_config(&root), uid, Arc::new(FakeChildSpawner::new()))
                .expect("reopen manager");
        assert!(reopened.broker_generation() > first_generation);
        drop(reopened);
        drop(listener);
        fs::remove_file(root.join("config").join(herdr_app_dir()).join("herdr.sock"))
            .expect("remove socket");
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::data_port_allocator_fails_closed_at_capacity]
    #[test]
    fn data_port_allocator_fails_closed_at_capacity() {
        let mut allocator = DataPortAllocator::new(BROKER_DATA_PORT_BASE, BROKER_DATA_PORT_LAST)
            .expect("allocator");
        for _ in 0..100 {
            allocator.reserve().expect("reserve data port");
        }
        assert!(matches!(
            allocator.reserve(),
            Err(RelayError::PortRangeExhausted)
        ));
        allocator.release(BROKER_DATA_PORT_BASE);
        assert_eq!(
            allocator.reserve().expect("reuse released port"),
            BROKER_DATA_PORT_BASE
        );
    }

    // TEST:relay/src/manager.rs[tests::state_excludes_tokens_and_fingerprints]
    #[tokio::test(flavor = "current_thread")]
    async fn state_excludes_tokens_and_fingerprints() {
        let (mut manager, _, listener, root) = test_manager("state").await;
        let grant = manager.ensure("default", 100).await.expect("ensure");
        let state_path = manager.config.manager_root().join(MANAGER_STATE_FILE);
        let state = fs::read_to_string(state_path).expect("state");
        assert!(!state.contains(&format!("{:?}", grant.token())));
        assert!(!state.contains(SESSION_FINGERPRINT_FILE));
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::launch_agent_contains_no_runtime_secret]
    #[test]
    fn launch_agent_contains_no_runtime_secret() {
        let root = test_root("plist");
        let config = test_config(&root);
        let uid = fs::symlink_metadata(&root).expect("root metadata").uid();
        let manager = Manager::with_spawner(config, uid, Arc::new(FakeChildSpawner::new()))
            .expect("open manager");
        let plist = manager
            .launch_agent_plist(&root.join("manager.toml"))
            .expect("render plist");
        assert!(plist.contains(LAUNCH_AGENT_LABEL));
        assert!(!plist.contains("lease"));
        assert!(!plist.contains("fingerprint"));
        fs::remove_dir_all(root).expect("remove test root");
    }

    // TEST:relay/src/manager.rs[tests::child_bootstrap_round_trip_redacts_token]
    #[test]
    fn child_bootstrap_round_trip_redacts_token() {
        let spec = ChildSpec {
            session: SessionName::normalize("work").expect("session"),
            generation: 7,
            data_port: BROKER_DATA_PORT_BASE,
            ipc_path: PathBuf::from("/tmp/child.sock"),
            parent_pid: 42,
            token: LeaseToken([9; 32]),
        };
        let frame = ChildBootstrap::encode(&spec).expect("encode");
        let decoded = ChildBootstrap::decode(&frame).expect("decode");
        assert_eq!(decoded.session, spec.session);
        assert_eq!(decoded.generation, spec.generation);
        assert_eq!(decoded.data_port, spec.data_port);
        assert!(!format!("{decoded:?}").contains("9"));
    }

    // TEST:relay/src/manager.rs[tests::generated_config_contains_explicit_safe_values]
    #[tokio::test(flavor = "current_thread")]
    async fn generated_config_contains_explicit_safe_values() {
        let (mut manager, _, listener, root) = test_manager("config-output").await;
        let grant = manager.ensure("default", 100).await.expect("ensure");
        assert_eq!(grant.configuration_generation(), 1);
        let config_path = root
            .join("manager")
            .join("sessions")
            .join("default")
            .join(SESSION_RELAY_CONFIG_FILE);
        let config = fs::read_to_string(config_path).expect("generated config");
        assert!(config.contains("port_base = 18743"));
        assert!(config.contains("enabled = false"));
        assert!(!config.contains(&format!("{:?}", grant.token())));
        drop(listener);
        fs::remove_dir_all(root).expect("remove test root");
    }

    /// Verifies that Manager-side bootstrap exchange times out while waiting for an ack.
    // TEST:relay/src/manager.rs[tests::child_bootstrap_exchange_timeout_is_bounded]
    #[tokio::test(flavor = "current_thread")]
    async fn child_bootstrap_exchange_timeout_is_bounded() {
        let (mut manager_stream, _peer_stream) = UnixStream::pair().expect("stream pair");
        let frame = ChildBootstrap::encode(&bootstrap_test_spec()).expect("encode bootstrap");
        let result =
            exchange_child_bootstrap(&mut manager_stream, &frame, Duration::from_millis(10)).await;
        assert!(matches!(
            result,
            Err(RelayError::ChildLifecycle {
                reason: "child bootstrap exchange timed out"
            })
        ));
    }

    /// Verifies that child-side bootstrap frame reads use the same bounded deadline.
    // TEST:relay/src/manager.rs[tests::child_bootstrap_read_timeout_is_bounded]
    #[tokio::test(flavor = "current_thread")]
    async fn child_bootstrap_read_timeout_is_bounded() {
        let (mut child_stream, _manager_stream) = UnixStream::pair().expect("stream pair");
        let session = SessionName::normalize("work").expect("session");
        let result = receive_child_bootstrap(
            &mut child_stream,
            &session,
            7,
            BROKER_DATA_PORT_BASE,
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(
            result,
            Err(RelayError::ChildLifecycle {
                reason: "child bootstrap exchange timed out"
            })
        ));
    }

    /// Verifies that a bootstrap acknowledgement mismatch is rejected terminally.
    // TEST:relay/src/manager.rs[tests::child_bootstrap_ack_mismatch_is_terminal]
    #[tokio::test(flavor = "current_thread")]
    async fn child_bootstrap_ack_mismatch_is_terminal() {
        let (mut manager_stream, mut child_stream) = UnixStream::pair().expect("stream pair");
        let frame = ChildBootstrap::encode(&bootstrap_test_spec()).expect("encode bootstrap");
        let frame_len = frame.len();
        let child = tokio::spawn(async move {
            let mut received = vec![0_u8; frame_len];
            child_stream
                .read_exact(&mut received)
                .await
                .expect("read bootstrap");
            child_stream
                .write_all(b"BAD!!")
                .await
                .expect("write invalid ack");
        });
        let result =
            exchange_child_bootstrap(&mut manager_stream, &frame, Duration::from_secs(1)).await;
        child.await.expect("child task");
        assert!(matches!(
            result,
            Err(RelayError::ChildLifecycle {
                reason: "child bootstrap acknowledgement is invalid"
            })
        ));
    }

    /// Verifies that parent-death polling observes a terminated parent process.
    // TEST:relay/src/manager.rs[tests::parent_death_polling_detects_exit]
    #[tokio::test(flavor = "current_thread")]
    async fn parent_death_polling_detects_exit() {
        let mut parent = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn short-lived parent");
        let parent_pid = parent.id().expect("parent pid");
        parent.wait().await.expect("wait parent");
        timeout(
            Duration::from_secs(1),
            wait_for_parent_death(parent_pid, Duration::from_millis(10)),
        )
        .await
        .expect("parent death polling");
    }
}
