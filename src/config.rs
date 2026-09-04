//! Strongly typed QRM-1 Relay configuration.
//!
//! The configuration has one generic UDP listener and one QUIC TLS policy. Network classes and
//! per-session port/process settings are intentionally absent from this public shape.

use crate::{
    error::{RelayError, RelayResult},
    iroh_endpoint::IrohRelayConfig,
    socket::UnixSocketConnector,
};
use serde::{Deserialize, Deserializer, de::Error as _};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

/// Default TOML template for the legacy certificate-era CLI commands.
///
/// The iroh `run` command uses [`DEFAULT_IROH_CONFIG_TOML`] instead; this constant remains for
/// callers that still need to inspect the retired update/revoke configuration template.
pub const DEFAULT_CONFIG_TOML: &str = include_str!("../config/default.toml");
/// Default TOML template for the iroh application Relay runtime.
pub const DEFAULT_IROH_CONFIG_TOML: &str = include_str!("../config/iroh-default.toml");

/// Provider profile selected by Core/admin provisioning for the application Relay.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IrohRelayProvider {
    /// Shared n0 public relays requiring no user-owned configuration.
    OfficialPublic,
    /// Iroh Services dedicated relays requiring a provisioned project secret reference.
    OfficialManaged,
    /// Operator-provided dedicated relays configured by the deployment owner.
    SelfHosted,
}

/// Fixed Herdr workspace verifier settings for the iroh Relay pairing path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IrohPairingConfig {
    /// Absolute Herdr Unix socket path used by the fixed verifier.
    socket_path: PathBuf,
    /// Expected owner UID for the Herdr Unix socket.
    expected_uid: u32,
    /// Normalized Herdr session used for verification workspaces.
    session: String,
    /// Protected absolute cwd supplied to verification workspaces.
    verification_cwd: PathBuf,
}

impl IrohPairingConfig {
    /// Return the configured Herdr Unix socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Return the expected Herdr Unix socket owner UID.
    pub const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }

    /// Return the normalized Herdr verification session.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Return the protected absolute verification cwd.
    pub fn verification_cwd(&self) -> &Path {
        &self.verification_cwd
    }
}

/// Provider and lifecycle configuration for the iroh application Relay runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IrohRuntimeConfig {
    /// Local IP and port used by the application Relay endpoint.
    #[serde(default = "default_iroh_bind_address")]
    bind_address: String,
    /// Core/admin-selected network-relay provider profile.
    #[serde(default = "default_iroh_provider")]
    provider: IrohRelayProvider,
    /// Bounded provisioned relay URL list for managed or self-hosted profiles.
    #[serde(default)]
    relay_urls: Vec<String>,
    /// Protected reference for an official managed project API key.
    #[serde(default)]
    api_secret_ref: Option<String>,
    /// Protected reference for a self-hosted access token, when required by its mode.
    #[serde(default)]
    access_token_ref: Option<String>,
    /// Maximum active Core connections accepted by the application Relay.
    #[serde(default = "default_iroh_max_connections")]
    max_connections: usize,
    /// Maximum active session streams permitted per Core connection.
    #[serde(default = "default_iroh_max_sessions")]
    max_sessions_per_connection: usize,
    /// Ordinary control-stream timeout in seconds.
    #[serde(default = "default_iroh_control_timeout_secs")]
    control_timeout_secs: u64,
    /// Nonzero Relay identity generation for the runtime.
    #[serde(default = "default_iroh_generation")]
    relay_generation: u64,
    /// Optional development-only local authority directory.
    #[serde(default)]
    development_recovery_directory: Option<PathBuf>,
    /// Optional fixed Herdr workspace verifier configuration.
    #[serde(default)]
    pairing: Option<IrohPairingConfig>,
}

/// Top-level TOML wrapper for the iroh runtime configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IrohRuntimeFile {
    /// Nested iroh runtime settings.
    iroh: IrohRuntimeConfig,
}

/// Default bind address for a local iroh application Relay.
fn default_iroh_bind_address() -> String {
    "127.0.0.1:18743".to_owned()
}

/// Default provider profile for development and public interoperability checks.
fn default_iroh_provider() -> IrohRelayProvider {
    IrohRelayProvider::OfficialPublic
}

/// Default bounded Core connection capacity.
fn default_iroh_max_connections() -> usize {
    64
}

/// Default bounded session-stream capacity.
fn default_iroh_max_sessions() -> usize {
    64
}

/// Default ordinary iroh control timeout.
fn default_iroh_control_timeout_secs() -> u64 {
    5
}

/// Default nonzero Relay identity generation.
fn default_iroh_generation() -> u64 {
    1
}

impl IrohRuntimeConfig {
    /// Parse and validate an iroh runtime TOML document.
    ///
    /// # Parameters
    /// * `contents` - TOML document containing one `[iroh]` section.
    ///
    /// # Returns
    /// A bounded runtime configuration or a redacted configuration error.
    // TEST:relay/src/config.rs[tests::iroh_runtime_configuration_matrix]
    pub fn from_toml_str(contents: &str) -> RelayResult<Self> {
        let file = toml::from_str::<IrohRuntimeFile>(contents)
            .map_err(|_| RelayError::ConfigurationSyntax)?;
        file.iroh.validate()?;
        Ok(file.iroh)
    }

    /// Read and validate an iroh runtime TOML file.
    ///
    /// # Parameters
    /// * `path` - Configuration file path.
    ///
    /// # Returns
    /// A bounded runtime configuration or a redacted read/validation error.
    pub fn from_path(path: &Path) -> RelayResult<Self> {
        let contents = fs::read_to_string(path).map_err(|_| RelayError::ConfigurationRead)?;
        Self::from_toml_str(&contents)
    }

    /// Override the configured bind port for a command-line invocation.
    ///
    /// # Parameters
    /// * `port` - Port selected by the caller; zero keeps an ephemeral listener valid for tests.
    ///
    /// # Returns
    /// A validated configuration with the same bind address and the requested port.
    pub fn with_bind_port(mut self, port: u16) -> RelayResult<Self> {
        let address = self.bind_address.parse::<SocketAddr>().map_err(|_| {
            RelayError::InvalidConfiguration {
                field: "iroh.bind_address",
                reason: "must be a socket address",
            }
        })?;
        self.bind_address = SocketAddr::new(address.ip(), port).to_string();
        self.validate()?;
        Ok(self)
    }

    /// Return the configured bind address.
    pub fn bind_address(&self) -> RelayResult<SocketAddr> {
        self.bind_address
            .parse::<SocketAddr>()
            .map_err(|_| RelayError::InvalidConfiguration {
                field: "iroh.bind_address",
                reason: "must be a socket address",
            })
    }

    /// Return the selected network-relay provider.
    pub const fn provider(&self) -> IrohRelayProvider {
        self.provider
    }

    /// Return the bounded provisioned relay URLs.
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Report whether an official managed API-key reference was configured.
    pub fn has_api_secret_ref(&self) -> bool {
        self.api_secret_ref.is_some()
    }

    /// Report whether a self-hosted access-token reference was configured.
    pub fn has_access_token_ref(&self) -> bool {
        self.access_token_ref.is_some()
    }

    /// Return the configured maximum Core connection count.
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Return the configured session-stream limit.
    pub const fn max_sessions_per_connection(&self) -> usize {
        self.max_sessions_per_connection
    }

    /// Return the ordinary control timeout.
    pub const fn control_timeout_secs(&self) -> u64 {
        self.control_timeout_secs
    }

    /// Return the configured Relay identity generation.
    pub const fn relay_generation(&self) -> u64 {
        self.relay_generation
    }

    /// Return the optional development-only recovery directory.
    pub fn development_recovery_directory(&self) -> Option<&Path> {
        self.development_recovery_directory.as_deref()
    }

    /// Return the optional fixed Herdr workspace verifier settings.
    pub fn pairing(&self) -> Option<&IrohPairingConfig> {
        self.pairing.as_ref()
    }

    /// Build the internal iroh endpoint policy from the validated TOML surface.
    ///
    /// # Returns
    /// A bounded endpoint configuration. Official managed hosting remains typed as unavailable
    /// until protected API-secret resolution is supplied by the Core/admin boundary.
    pub fn to_endpoint_config(&self) -> RelayResult<IrohRelayConfig> {
        let control_timeout = std::time::Duration::from_secs(self.control_timeout_secs);
        let mut config = IrohRelayConfig::new(
            self.max_connections,
            self.max_sessions_per_connection,
            control_timeout,
        )
        .map_err(RelayError::from)?
        .with_bind_addr(self.bind_address()?);
        config = config
            .with_relay_generation(self.relay_generation)
            .map_err(RelayError::from)?;
        match self.provider {
            IrohRelayProvider::OfficialPublic => {}
            IrohRelayProvider::OfficialManaged => {
                return Err(RelayError::IrohEndpoint {
                    reason: "provider_unavailable",
                });
            }
            IrohRelayProvider::SelfHosted => {
                if self.access_token_ref.is_some() {
                    // Secret resolution is owned by the later Core/admin boundary; fail closed
                    // until the selected access mode can receive its protected token.
                    return Err(RelayError::IrohEndpoint {
                        reason: "provider_unavailable",
                    });
                }
                config = config
                    .with_relay_urls(&self.relay_urls)
                    .map_err(RelayError::from)?;
            }
        }
        if let Some(pairing) = self.pairing.as_ref() {
            let connector =
                UnixSocketConnector::new(pairing.socket_path.clone(), pairing.expected_uid)
                    .map_err(|_| RelayError::InvalidConfiguration {
                        field: "iroh.pairing.socket_path",
                        reason: "must be an absolute validated Unix socket path",
                    })?;
            config = config.with_socket_connector(connector);
        }
        if let Some(root) = self.development_recovery_directory.as_ref() {
            config = config
                .with_development_recovery_dir(root)
                .map_err(RelayError::from)?;
        }
        Ok(config)
    }

    /// Return the optional fixed Herdr workspace verifier configuration for endpoint wiring.
    pub fn pairing_config(&self) -> Option<&IrohPairingConfig> {
        self.pairing.as_ref()
    }

    /// Validate provider, resource, path and verifier invariants without side effects.
    fn validate(&self) -> RelayResult<()> {
        if self.bind_address.parse::<SocketAddr>().is_err() {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.bind_address",
                reason: "must be a socket address",
            });
        }
        if self.relay_generation == 0 {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.relay_generation",
                reason: "must be nonzero",
            });
        }
        if self.max_connections == 0 || self.max_connections > 64 {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.max_connections",
                reason: "must be between 1 and 64",
            });
        }
        if self.max_sessions_per_connection == 0 || self.max_sessions_per_connection > 64 {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.max_sessions_per_connection",
                reason: "must be between 1 and 64",
            });
        }
        if self.control_timeout_secs == 0 || self.control_timeout_secs > 30 {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.control_timeout_secs",
                reason: "must be between 1 and 30 seconds",
            });
        }
        if self.relay_urls.len() > 4 {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.relay_urls",
                reason: "must contain at most four URLs",
            });
        }
        if self.relay_urls.iter().any(|url| {
            url.is_empty()
                || url.len() > 512
                || !url.is_ascii()
                || url.chars().any(|character| character.is_whitespace())
        }) {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.relay_urls",
                reason: "must contain bounded non-whitespace ASCII URLs",
            });
        }
        if self.api_secret_ref.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 128
                || !value.is_ascii()
                || value.chars().any(|character| character.is_whitespace())
        }) {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.api_secret_ref",
                reason: "must be a bounded non-whitespace ASCII reference",
            });
        }
        if self.access_token_ref.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 128
                || !value.is_ascii()
                || value.chars().any(|character| character.is_whitespace())
        }) {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.access_token_ref",
                reason: "must be a bounded non-whitespace ASCII reference",
            });
        }
        match self.provider {
            IrohRelayProvider::OfficialPublic => {
                if !self.relay_urls.is_empty()
                    || self.api_secret_ref.is_some()
                    || self.access_token_ref.is_some()
                {
                    return Err(RelayError::InvalidConfiguration {
                        field: "iroh.provider",
                        reason: "official_public does not accept URL or credential fields",
                    });
                }
            }
            IrohRelayProvider::OfficialManaged => {
                if self.relay_urls.is_empty()
                    || self.api_secret_ref.is_none()
                    || self.access_token_ref.is_some()
                {
                    return Err(RelayError::InvalidConfiguration {
                        field: "iroh.provider",
                        reason: "official_managed requires relay URLs and api_secret_ref only",
                    });
                }
            }
            IrohRelayProvider::SelfHosted => {
                if self.relay_urls.is_empty() || self.api_secret_ref.is_some() {
                    return Err(RelayError::InvalidConfiguration {
                        field: "iroh.provider",
                        reason: "self_hosted requires relay URLs and forbids api_secret_ref",
                    });
                }
            }
        }
        if let Some(directory) = self.development_recovery_directory.as_ref()
            && !directory.is_absolute()
        {
            return Err(RelayError::InvalidConfiguration {
                field: "iroh.development_recovery_directory",
                reason: "must be absolute",
            });
        }
        if let Some(pairing) = self.pairing.as_ref() {
            if !pairing.socket_path.is_absolute() {
                return Err(RelayError::InvalidConfiguration {
                    field: "iroh.pairing.socket_path",
                    reason: "must be absolute",
                });
            }
            if !pairing.verification_cwd.is_absolute() {
                return Err(RelayError::InvalidConfiguration {
                    field: "iroh.pairing.verification_cwd",
                    reason: "must be absolute",
                });
            }
            if pairing.session.is_empty()
                || pairing.session.len() > 64
                || pairing.session == "."
                || pairing.session == ".."
            {
                return Err(RelayError::InvalidConfiguration {
                    field: "iroh.pairing.session",
                    reason: "must be a bounded normalized session",
                });
            }
            if !pairing
                .session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(RelayError::InvalidConfiguration {
                    field: "iroh.pairing.session",
                    reason: "contains unsupported characters",
                });
            }
        }
        Ok(())
    }
}

/// The default single-device UDP port.
pub const QRM_DEFAULT_PORT: u16 = 18_743;
/// The maximum complete HDQM frame size.
pub const QRM_MAX_CONTROL_FRAME_BYTES: usize = 65_536;
/// The maximum per-direction opaque bridge buffer.
pub const QRM_BUFFER_BYTES: usize = 65_536;
/// The maximum total Core connections.
pub const QRM_MAX_CONNECTIONS: usize = 64;
/// The maximum session streams per connection.
pub const QRM_MAX_SESSIONS_PER_CONNECTION: usize = 64;
/// The bounded handshake/session bind timeout.
pub const QRM_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
/// The bounded QUIC idle timeout.
pub const QRM_IDLE_TIMEOUT_SECS: u64 = 900;
/// The maximum bounded enrollment request frame.
pub const QRM_MAX_ENROLLMENT_REQUEST_BYTES: usize = 65_536;
/// The maximum raw CSR size accepted during enrollment.
pub const QRM_MAX_ENROLLMENT_CSR_BYTES: usize = 16_384;
/// The maximum concurrent pre-authenticated enrollment handshakes.
pub const QRM_MAX_ENROLLMENT_HANDSHAKES: usize = 16;
/// The maximum concurrent enrollment connections.
pub const QRM_MAX_ENROLLMENT_CONNECTIONS: usize = 8;
/// The maximum enrollment connection lifetime in seconds, including human code entry.
pub const QRM_MAX_ENROLLMENT_LIFETIME_SECS: u64 = 330;
/// The maximum enrollment challenge lifetime in seconds.
pub const QRM_MAX_ENROLLMENT_CHALLENGE_TTL_SECS: u64 = 300;
/// The maximum downloaded updater archive size.
pub const QRM_MAX_UPDATE_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// The maximum extracted updater tree size.
pub const QRM_MAX_UPDATE_EXTRACTED_BYTES: u64 = 128 * 1024 * 1024;
/// The maximum extracted updater entry count.
pub const QRM_MAX_UPDATE_ENTRIES: usize = 32;
/// The maximum allowed decompression ratio.
pub const QRM_MAX_UPDATE_COMPRESSION_RATIO: u64 = 100;

/// TLS policy selected by a configuration file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityMode {
    /// Production certificate-chain, hostname and client-identity verification.
    Verified,
    /// Test-only TLS with trust verification relaxed but encryption retained.
    DevelopmentUnverified,
}

impl<'de> Deserialize<'de> for SecurityMode {
    /// Parses one explicit security mode without accepting aliases.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "verified" => Ok(Self::Verified),
            "development_unverified" => Ok(Self::DevelopmentUnverified),
            _ => Err(D::Error::custom("unsupported QRM security mode")),
        }
    }
}

/// One generic UDP listener configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Explicit local bind address.
    listen_address: String,
    /// One UDP port for the remote device.
    port: u16,
}

impl ListenerConfig {
    /// Parses the configured local socket address.
    ///
    /// # Returns
    /// A non-zero UDP bind address or a redacted configuration error.
    pub fn socket_addr(&self) -> RelayResult<SocketAddr> {
        let ip: IpAddr =
            self.listen_address
                .parse()
                .map_err(|_| RelayError::InvalidConfiguration {
                    field: "listener.listen_address",
                    reason: "must be an IP address",
                })?;
        if self.port == 0 {
            return Err(RelayError::InvalidConfiguration {
                field: "listener.port",
                reason: "must be a non-zero UDP port",
            });
        }
        Ok(SocketAddr::new(ip, self.port))
    }

    /// Returns the configured UDP port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// The default protected trust-bundle generation.
fn default_ca_generation() -> u64 {
    1
}

/// TLS certificate and trust references.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Explicit TLS mode.
    mode: SecurityMode,
    /// Non-secret trust-bundle generation advertised during the QRM hello.
    #[serde(default = "default_ca_generation")]
    ca_generation: u64,
    /// Absolute path to the Relay certificate chain.
    server_certificate: PathBuf,
    /// Absolute path to the Relay private key.
    server_private_key: PathBuf,
    /// Absolute path to the trusted Core client CA.
    trusted_client_ca: PathBuf,
    /// Absolute path to the trusted Core client CA used by enrollment.
    #[serde(default)]
    trusted_core_enrollment_ca: PathBuf,
    /// Absolute path to the Core-enrollment Intermediate CA certificate used for HDB1 issuance.
    #[serde(default)]
    core_enrollment_intermediate_certificate: PathBuf,
    /// Absolute path to the Core-enrollment Intermediate CA private key.
    #[serde(default)]
    core_enrollment_intermediate_private_key: PathBuf,
    /// Absolute path to the device Intermediate CA certificate chain.
    #[serde(default)]
    device_intermediate_certificate: PathBuf,
    /// Absolute path to the device Intermediate CA private key.
    #[serde(default)]
    device_intermediate_private_key: PathBuf,
    /// Absolute path to the public Root CA chain returned to enrolled Apps.
    #[serde(default)]
    public_root_certificate: PathBuf,
}

impl SecurityConfig {
    /// Returns the configured TLS mode.
    pub const fn mode(&self) -> SecurityMode {
        self.mode
    }

    /// Returns the configured trust-bundle generation.
    pub const fn ca_generation(&self) -> u64 {
        self.ca_generation
    }

    /// Returns the configured certificate path.
    pub fn server_certificate(&self) -> &Path {
        &self.server_certificate
    }

    /// Returns the configured private-key path.
    pub fn server_private_key(&self) -> &Path {
        &self.server_private_key
    }

    /// Returns the trusted Core enrollment CA path.
    pub fn trusted_core_enrollment_ca(&self) -> &Path {
        &self.trusted_core_enrollment_ca
    }

    /// Returns the Core-enrollment Intermediate CA certificate path.
    pub fn core_enrollment_intermediate_certificate(&self) -> &Path {
        &self.core_enrollment_intermediate_certificate
    }

    /// Returns the Core-enrollment Intermediate CA private-key path.
    pub fn core_enrollment_intermediate_private_key(&self) -> &Path {
        &self.core_enrollment_intermediate_private_key
    }

    /// Returns the configured device Intermediate CA certificate path.
    pub fn device_intermediate_certificate(&self) -> &Path {
        &self.device_intermediate_certificate
    }

    /// Returns the configured device Intermediate CA private-key path.
    pub fn device_intermediate_private_key(&self) -> &Path {
        &self.device_intermediate_private_key
    }

    /// Returns the configured public Root CA certificate path.
    pub fn public_root_certificate(&self) -> &Path {
        &self.public_root_certificate
    }

    /// Returns the configured client CA path.
    pub fn trusted_client_ca(&self) -> &Path {
        &self.trusted_client_ca
    }
}

/// Bounded Relay resource limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum total Core connections.
    max_connections: usize,
    /// Maximum session streams per connection.
    max_sessions_per_connection: usize,
    /// Maximum complete HDQM frame.
    max_control_frame_bytes: usize,
    /// Maximum per-direction bridge buffer.
    buffer_bytes: usize,
    /// Handshake/session bind timeout in seconds.
    handshake_timeout_secs: u64,
    /// QUIC idle timeout in seconds.
    idle_timeout_secs: u64,
}

impl ResourceLimits {
    /// Validates all fixed QRM resource bounds.
    pub fn validate(&self) -> RelayResult<()> {
        if self.max_connections == 0 || self.max_connections > QRM_MAX_CONNECTIONS {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.max_connections",
                reason: "must be between 1 and the QRM connection limit",
            });
        }
        if self.max_sessions_per_connection == 0
            || self.max_sessions_per_connection > QRM_MAX_SESSIONS_PER_CONNECTION
        {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.max_sessions_per_connection",
                reason: "must be between 1 and the QRM session limit",
            });
        }
        if self.max_control_frame_bytes != QRM_MAX_CONTROL_FRAME_BYTES
            || self.buffer_bytes == 0
            || self.buffer_bytes > QRM_BUFFER_BYTES
        {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.max_control_frame_bytes",
                reason: "must equal the fixed QRM control-frame limit and keep buffers within bounds",
            });
        }
        if self.handshake_timeout_secs == 0
            || self.handshake_timeout_secs > QRM_HANDSHAKE_TIMEOUT_SECS
            || self.idle_timeout_secs == 0
            || self.idle_timeout_secs > QRM_IDLE_TIMEOUT_SECS
        {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.handshake_timeout_secs",
                reason: "timeouts exceed the QRM bounds",
            });
        }
        Ok(())
    }

    /// Returns the maximum total connection count.
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }
    /// Returns the maximum session count per connection.
    pub const fn max_sessions_per_connection(&self) -> usize {
        self.max_sessions_per_connection
    }
    /// Returns the complete control-frame limit.
    pub const fn max_control_frame_bytes(&self) -> usize {
        self.max_control_frame_bytes
    }
    /// Returns the per-direction bridge buffer.
    pub const fn buffer_bytes(&self) -> usize {
        self.buffer_bytes
    }
    /// Returns the handshake timeout in seconds.
    pub const fn handshake_timeout_secs(&self) -> u64 {
        self.handshake_timeout_secs
    }
    /// Returns the idle timeout in seconds.
    pub const fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }
}

/// Bounded same-port enrollment settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnrollmentConfig {
    /// Enables production enrollment handling on the enrollment ALPN.
    enabled: bool,
    /// Absolute path to the protected non-secret App allowlist.
    allowlist_path: PathBuf,
    /// Absolute protected path for response-lost issuance reconciliation records.
    #[serde(default)]
    issuance_result_path: PathBuf,
    /// Absolute protected path for restart-surviving HDB1 bootstrap metadata.
    #[serde(default = "default_bootstrap_state_path")]
    bootstrap_state_path: PathBuf,
    /// Maximum pre-authenticated enrollment handshakes.
    max_handshakes: usize,
    /// Maximum enrollment connections after TLS/ALPN selection.
    max_connections: usize,
    /// Maximum complete enrollment request frame.
    max_request_bytes: usize,
    /// Maximum raw CSR bytes retained transiently.
    max_csr_bytes: usize,
    /// Maximum lifetime of one enrollment connection.
    connection_lifetime_secs: u64,
    /// Maximum lifetime of one Relay challenge.
    challenge_ttl_secs: u64,
    /// Normalized Herdr session used by server-only bootstrap and later approval.
    #[serde(default = "default_bootstrap_session")]
    bootstrap_session: String,
    /// Remote absolute cwd used by the bounded hidden verification workspace.
    #[serde(default = "default_bootstrap_verification_cwd")]
    bootstrap_verification_cwd: String,
}

fn default_bootstrap_session() -> String {
    "default".to_owned()
}

fn default_bootstrap_verification_cwd() -> String {
    "/path/to/herdr-dog/bootstrap-verification".to_owned()
}

fn default_bootstrap_state_path() -> PathBuf {
    PathBuf::from("/path/to/herdr-dog/bootstrap-state.json")
}

impl Default for EnrollmentConfig {
    /// Returns the fail-closed configuration used by legacy test fixtures.
    fn default() -> Self {
        Self {
            enabled: false,
            allowlist_path: PathBuf::new(),
            issuance_result_path: PathBuf::new(),
            bootstrap_state_path: default_bootstrap_state_path(),
            max_handshakes: QRM_MAX_ENROLLMENT_HANDSHAKES,
            max_connections: QRM_MAX_ENROLLMENT_CONNECTIONS,
            max_request_bytes: QRM_MAX_ENROLLMENT_REQUEST_BYTES,
            max_csr_bytes: QRM_MAX_ENROLLMENT_CSR_BYTES,
            connection_lifetime_secs: QRM_MAX_ENROLLMENT_LIFETIME_SECS,
            challenge_ttl_secs: QRM_MAX_ENROLLMENT_CHALLENGE_TTL_SECS,
            bootstrap_session: default_bootstrap_session(),
            bootstrap_verification_cwd: default_bootstrap_verification_cwd(),
        }
    }
}

impl EnrollmentConfig {
    /// Validates all bounded enrollment settings before listener binding.
    pub fn validate(&self) -> RelayResult<()> {
        if !self.enabled {
            return Ok(());
        }
        validate_absolute_path("enrollment.allowlist_path", &self.allowlist_path)?;
        validate_absolute_path(
            "enrollment.issuance_result_path",
            &self.issuance_result_path,
        )?;
        validate_absolute_path(
            "enrollment.bootstrap_state_path",
            &self.bootstrap_state_path,
        )?;
        if self.max_handshakes == 0 || self.max_handshakes > QRM_MAX_ENROLLMENT_HANDSHAKES {
            return Err(RelayError::InvalidConfiguration {
                field: "enrollment.max_handshakes",
                reason: "exceeds the fixed enrollment handshake bound",
            });
        }
        if self.max_connections == 0 || self.max_connections > QRM_MAX_ENROLLMENT_CONNECTIONS {
            return Err(RelayError::InvalidConfiguration {
                field: "enrollment.max_connections",
                reason: "exceeds the fixed enrollment connection bound",
            });
        }
        if self.max_request_bytes != QRM_MAX_ENROLLMENT_REQUEST_BYTES
            || self.max_csr_bytes == 0
            || self.max_csr_bytes > QRM_MAX_ENROLLMENT_CSR_BYTES
            || self.connection_lifetime_secs == 0
            || self.connection_lifetime_secs > QRM_MAX_ENROLLMENT_LIFETIME_SECS
            || self.challenge_ttl_secs == 0
            || self.challenge_ttl_secs > QRM_MAX_ENROLLMENT_CHALLENGE_TTL_SECS
        {
            return Err(RelayError::InvalidConfiguration {
                field: "enrollment.max_request_bytes",
                reason: "enrollment bounds exceed the fixed QRM limits",
            });
        }
        if !is_valid_bootstrap_session(&self.bootstrap_session)
            || self.bootstrap_verification_cwd.is_empty()
            || !Path::new(&self.bootstrap_verification_cwd).is_absolute()
            || self.bootstrap_verification_cwd.contains('\n')
            || self.bootstrap_verification_cwd.contains('\r')
        {
            return Err(RelayError::InvalidConfiguration {
                field: "enrollment.bootstrap_verification_cwd",
                reason: "bootstrap workspace configuration is invalid",
            });
        }
        Ok(())
    }

    /// Returns whether the production enrollment path is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the protected allowlist path.
    pub fn allowlist_path(&self) -> &Path {
        &self.allowlist_path
    }

    /// Returns the protected issuance-result path.
    pub fn issuance_result_path(&self) -> &Path {
        &self.issuance_result_path
    }

    /// Returns the protected bootstrap state path.
    pub fn bootstrap_state_path(&self) -> &Path {
        &self.bootstrap_state_path
    }

    /// Returns the pre-authentication semaphore bound.
    pub const fn max_handshakes(&self) -> usize {
        self.max_handshakes
    }

    /// Returns the post-ALPN enrollment connection bound.
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the complete enrollment frame bound.
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    /// Returns the transient CSR byte bound.
    pub const fn max_csr_bytes(&self) -> usize {
        self.max_csr_bytes
    }

    /// Returns the enrollment connection lifetime.
    pub const fn connection_lifetime_secs(&self) -> u64 {
        self.connection_lifetime_secs
    }

    /// Returns the challenge lifetime.
    pub const fn challenge_ttl_secs(&self) -> u64 {
        self.challenge_ttl_secs
    }

    /// Returns the normalized session used by HDB1/HDE3 bootstrap verification.
    pub fn bootstrap_session(&self) -> &str {
        &self.bootstrap_session
    }

    /// Returns the remote cwd used by the hidden verification workspace.
    pub fn bootstrap_verification_cwd(&self) -> &str {
        &self.bootstrap_verification_cwd
    }
}

fn is_valid_bootstrap_session(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Fixed-source stable-latest updater settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// Enables the local update worker and its fixed-source control surface.
    enabled: bool,
    /// Fixed GitHub owner/repository; arbitrary origins are rejected.
    repository: String,
    /// Fixed release selector accepted by the worker.
    channel: String,
    /// Protected staging directory outside the install directory.
    staging_directory: PathBuf,
    /// Maximum downloaded archive bytes.
    max_archive_bytes: u64,
    /// Maximum extracted tree bytes.
    max_extracted_bytes: u64,
    /// Maximum extracted entry count.
    max_entries: usize,
    /// Maximum archive decompression ratio.
    max_compression_ratio: u64,
}

impl Default for UpdateConfig {
    /// Returns the fail-closed updater defaults used by test fixtures.
    fn default() -> Self {
        Self {
            enabled: false,
            repository: "mithyer/herdr-dog-relay".to_owned(),
            channel: "stable-latest".to_owned(),
            staging_directory: PathBuf::new(),
            max_archive_bytes: QRM_MAX_UPDATE_ARCHIVE_BYTES,
            max_extracted_bytes: QRM_MAX_UPDATE_EXTRACTED_BYTES,
            max_entries: QRM_MAX_UPDATE_ENTRIES,
            max_compression_ratio: QRM_MAX_UPDATE_COMPRESSION_RATIO,
        }
    }
}

impl UpdateConfig {
    /// Validates fixed-source updater policy before it can be exposed.
    pub fn validate(&self) -> RelayResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.repository != "mithyer/herdr-dog-relay" || self.channel != "stable-latest" {
            return Err(RelayError::InvalidConfiguration {
                field: "update.repository",
                reason: "only the fixed stable-latest source is supported",
            });
        }
        validate_absolute_path("update.staging_directory", &self.staging_directory)?;
        if self.max_archive_bytes == 0
            || self.max_archive_bytes > QRM_MAX_UPDATE_ARCHIVE_BYTES
            || self.max_extracted_bytes == 0
            || self.max_extracted_bytes > QRM_MAX_UPDATE_EXTRACTED_BYTES
            || self.max_entries == 0
            || self.max_entries > QRM_MAX_UPDATE_ENTRIES
            || self.max_compression_ratio == 0
            || self.max_compression_ratio > QRM_MAX_UPDATE_COMPRESSION_RATIO
        {
            return Err(RelayError::InvalidConfiguration {
                field: "update.max_archive_bytes",
                reason: "updater limits exceed the fixed QRM bounds",
            });
        }
        Ok(())
    }

    /// Returns whether the fixed-source updater is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the fixed GitHub repository.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the only accepted update channel.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Returns the protected updater staging directory.
    pub fn staging_directory(&self) -> &Path {
        &self.staging_directory
    }

    /// Returns the maximum archive size.
    pub const fn max_archive_bytes(&self) -> u64 {
        self.max_archive_bytes
    }

    /// Returns the maximum extracted tree size.
    pub const fn max_extracted_bytes(&self) -> u64 {
        self.max_extracted_bytes
    }

    /// Returns the maximum extracted entry count.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the maximum decompression ratio.
    pub const fn max_compression_ratio(&self) -> u64 {
        self.max_compression_ratio
    }

    /// Builds an enabled updater policy for in-crate safety tests.
    #[cfg(test)]
    pub(crate) fn from_toml_for_test(staging_directory: PathBuf) -> Self {
        Self {
            enabled: true,
            staging_directory,
            ..Self::default()
        }
    }
}

/// Validated QRM-1 Relay configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Generic UDP listener settings.
    listener: ListenerConfig,
    /// QUIC TLS security settings.
    security: SecurityConfig,
    /// Bounded listener/session resource settings.
    limits: ResourceLimits,
    /// Same-port enrollment settings.
    #[serde(default)]
    enrollment: EnrollmentConfig,
    /// Fixed-source stable-latest updater settings.
    #[serde(default)]
    update: UpdateConfig,
}

impl RelayConfig {
    /// Parses and validates one complete TOML configuration.
    pub fn from_toml_str(input: &str) -> RelayResult<Self> {
        let config: Self = toml::from_str(input).map_err(|_| RelayError::ConfigurationSyntax)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses and validates a configuration file.
    pub fn from_path(path: &Path) -> RelayResult<Self> {
        let input = fs::read_to_string(path).map_err(|_| RelayError::ConfigurationRead)?;
        Self::from_toml_str(&input)
    }

    /// Validates the configuration before a listener is opened.
    pub fn validate(&self) -> RelayResult<()> {
        self.listener.socket_addr()?;
        self.limits.validate()?;
        self.enrollment.validate()?;
        self.update.validate()?;
        if self.security.ca_generation == 0 {
            return Err(RelayError::InvalidConfiguration {
                field: "security.ca_generation",
                reason: "must be non-zero",
            });
        }
        if self.security.mode == SecurityMode::Verified {
            validate_absolute_path(
                "security.server_certificate",
                &self.security.server_certificate,
            )?;
            validate_absolute_path(
                "security.server_private_key",
                &self.security.server_private_key,
            )?;
            validate_absolute_path(
                "security.trusted_client_ca",
                &self.security.trusted_client_ca,
            )?;
            // Normal QRM must always load an allowlist, even when new enrollment is disabled.
            validate_absolute_path("enrollment.allowlist_path", &self.enrollment.allowlist_path)?;
            if self.enrollment.enabled {
                validate_absolute_path(
                    "security.trusted_core_enrollment_ca",
                    &self.security.trusted_core_enrollment_ca,
                )?;
                validate_absolute_path(
                    "security.core_enrollment_intermediate_certificate",
                    &self.security.core_enrollment_intermediate_certificate,
                )?;
                validate_absolute_path(
                    "security.core_enrollment_intermediate_private_key",
                    &self.security.core_enrollment_intermediate_private_key,
                )?;
                validate_absolute_path(
                    "security.device_intermediate_certificate",
                    &self.security.device_intermediate_certificate,
                )?;
                validate_absolute_path(
                    "security.device_intermediate_private_key",
                    &self.security.device_intermediate_private_key,
                )?;
                validate_absolute_path(
                    "security.public_root_certificate",
                    &self.security.public_root_certificate,
                )?;
            }
        }
        Ok(())
    }

    /// Returns a validated copy with one explicit CLI port override.
    ///
    /// # Parameters
    /// * `port` - Non-zero UDP port supplied by `--port`.
    ///
    /// # Returns
    /// A configuration copy or a redacted validation error.
    pub fn with_port(mut self, port: u16) -> RelayResult<Self> {
        if port == 0 {
            return Err(RelayError::InvalidConfiguration {
                field: "listener.port",
                reason: "must be a non-zero UDP port",
            });
        }
        self.listener.port = port;
        self.validate()?;
        Ok(self)
    }

    /// Returns the validated listener settings.
    pub const fn listener(&self) -> &ListenerConfig {
        &self.listener
    }
    /// Returns the validated security settings.
    pub const fn security(&self) -> &SecurityConfig {
        &self.security
    }
    /// Returns the validated resource settings.
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Returns the bounded enrollment settings.
    pub const fn enrollment(&self) -> &EnrollmentConfig {
        &self.enrollment
    }

    /// Returns the fixed-source updater settings.
    pub const fn update(&self) -> &UpdateConfig {
        &self.update
    }
}

/// Validates an absolute non-root path before it can be used by a platform adapter.
pub fn validate_absolute_path(field: &'static str, path: &Path) -> RelayResult<()> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(RelayError::InvalidConfiguration {
            field,
            reason: "must be an absolute non-root path",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[listener]
listen_address = "127.0.0.1"
port = 18743

[security]
mode = "development_unverified"
server_certificate = "/tmp/server.pem"
server_private_key = "/tmp/server.key"
trusted_client_ca = "/tmp/client-ca.pem"

[limits]
max_connections = 64
max_sessions_per_connection = 64
max_control_frame_bytes = 65536
buffer_bytes = 65536
handshake_timeout_secs = 5
idle_timeout_secs = 900
"#;

    // TEST:relay/src/config.rs[tests::iroh_runtime_configuration_matrix]
    #[test]
    fn iroh_runtime_configuration_matrix() {
        let parse = |body: &str| IrohRuntimeConfig::from_toml_str(&format!("[iroh]\n{body}"));
        let public = parse("").expect("official public defaults");
        assert_eq!(public.provider(), IrohRelayProvider::OfficialPublic);
        assert_eq!(
            public
                .with_bind_port(18_744)
                .unwrap()
                .bind_address()
                .unwrap()
                .port(),
            18_744
        );
        assert!(parse("relay_urls = [\"https://relay.example.test\"]").is_err());
        assert!(parse("api_secret_ref = \"secret/ref\"").is_err());
        assert!(parse("access_token_ref = \"secret/ref\"").is_err());
        assert!(
            parse("provider = \"official_managed\"\nrelay_urls = [\"https://relay.example.test\"]")
                .is_err()
        );

        let managed = parse("provider = \"official_managed\"\nrelay_urls = [\"https://relay.example.test\"]\napi_secret_ref = \"secret/ref\"").expect("managed profile");
        assert!(matches!(
            managed.to_endpoint_config(),
            Err(RelayError::IrohEndpoint {
                reason: "provider_unavailable"
            })
        ));
        let self_hosted =
            parse("provider = \"self_hosted\"\nrelay_urls = [\"https://relay.example.test\"]")
                .expect("self-hosted profile");
        assert!(self_hosted.to_endpoint_config().is_ok());
        let self_hosted_auth = parse("provider = \"self_hosted\"\nrelay_urls = [\"https://relay.example.test\"]\naccess_token_ref = \"secret/ref\"").expect("self-hosted auth profile");
        assert!(matches!(
            self_hosted_auth.to_endpoint_config(),
            Err(RelayError::IrohEndpoint {
                reason: "provider_unavailable"
            })
        ));

        // Relative pairing paths are rejected before endpoint construction.
        assert!(parse("[iroh.pairing]\nsocket_path = \"relative.sock\"\nexpected_uid = 1\nsession = \"default\"\nverification_cwd = \"/tmp\"").is_err());
        // Relative recovery roots cannot scope authority records safely.
        assert!(parse("development_recovery_directory = \"relative\"").is_err());
        let defaults =
            IrohRuntimeConfig::from_toml_str(DEFAULT_IROH_CONFIG_TOML).expect("default template");
        assert_eq!(defaults.bind_address().unwrap().port(), 18_743);
        assert!(defaults.to_endpoint_config().is_ok());
    }

    // TEST:relay/src/config.rs[tests::qrm_config_has_one_listener]
    #[test]
    fn qrm_config_has_one_listener() {
        let config = RelayConfig::from_toml_str(VALID).expect("valid QRM config");
        assert_eq!(config.listener().socket_addr().unwrap().port(), 18743);
        assert_eq!(config.limits().max_sessions_per_connection(), 64);
    }

    // TEST:relay/src/config.rs[tests::ca_generation_is_nonzero_and_explicit]
    #[test]
    fn ca_generation_is_nonzero_and_explicit() {
        let defaulted = RelayConfig::from_toml_str(VALID).expect("default trust generation");
        assert_eq!(defaulted.security().ca_generation(), 1);
        let explicit = VALID.replace(
            "mode = \"development_unverified\"",
            "mode = \"development_unverified\"\nca_generation = 7",
        );
        assert_eq!(
            RelayConfig::from_toml_str(&explicit)
                .expect("explicit trust generation")
                .security()
                .ca_generation(),
            7
        );
        let zero = explicit.replace("ca_generation = 7", "ca_generation = 0");
        assert!(RelayConfig::from_toml_str(&zero).is_err());
    }

    // TEST:relay/src/config.rs[tests::legacy_network_tables_are_rejected]
    #[test]
    fn legacy_network_tables_are_rejected() {
        let invalid = VALID.replace("[limits]", "[network]\nclass = \"tailscale\"\n\n[limits]");
        assert!(RelayConfig::from_toml_str(&invalid).is_err());
    }

    // TEST:relay/src/config.rs[tests::plaintext_mode_is_not_a_value]
    #[test]
    fn plaintext_mode_is_not_a_value() {
        let invalid = VALID.replace("development_unverified", "tls_off");
        assert!(RelayConfig::from_toml_str(&invalid).is_err());
    }

    // TEST:relay/src/config.rs[tests::verified_mode_requires_allowlist_even_when_enrollment_is_disabled]
    #[test]
    fn verified_mode_requires_allowlist_even_when_enrollment_is_disabled() {
        let verified_without_allowlist = VALID.replace("development_unverified", "verified");
        assert!(RelayConfig::from_toml_str(&verified_without_allowlist).is_err());
        // Disabling enrollment only removes the enrollment ALPN; it cannot weaken normal QRM admission.
        let verified_with_allowlist = verified_without_allowlist.replace(
            "[limits]",
            "[enrollment]\nenabled = false\nallowlist_path = \"/tmp/allowlist.json\"\n\n[limits]",
        );
        assert!(RelayConfig::from_toml_str(&verified_with_allowlist).is_ok());
    }
}
