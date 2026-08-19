//! Strongly typed, fail-closed relay configuration.

use crate::error::{RelayError, RelayResult};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de::Error as _};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

/// The v1 listener base port shared by Relay and Core.
pub const V1_PORT_BASE: u16 = 18_743;
/// The exact number of v1 listener candidates.
pub const V1_PORT_ATTEMPTS: u8 = 10;
/// The inclusive last v1 listener candidate.
pub const V1_PORT_LAST: u16 = V1_PORT_BASE + V1_PORT_ATTEMPTS as u16 - 1;
/// The maximum number of complete App discovery sweeps.
pub const V1_MAX_DISCOVERY_SWEEPS: u8 = 3;
/// The v1 Relay protocol version.
pub const V1_RELAY_PROTOCOL_VERSION: u16 = 1;
/// The v1 TLS ALPN identifier.
pub const V1_RELAY_ALPN: &[u8] = b"herdr-dog-relay/1";
/// The v1 handshake deadline in seconds.
pub const V1_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
/// The v1 App probe deadline in seconds.
pub const V1_PROBE_TIMEOUT_SECS: u64 = 2;
/// The v1 global client limit.
pub const V1_MAX_CLIENTS: u16 = 64;
/// The v1 per-listener client limit.
pub const V1_MAX_CLIENTS_PER_LISTENER: u16 = 32;
/// The v1 concurrent unauthenticated handshake limit.
pub const V1_MAX_HANDSHAKES: u16 = 16;
/// The v1 per-direction forwarding buffer size.
pub const V1_BUFFER_BYTES: usize = 64 * 1024;
/// The v1 stream idle timeout in seconds.
pub const V1_IDLE_TIMEOUT_SECS: u64 = 15 * 60;
/// The v1 maximum diagnostic record size.
pub const V1_MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// The maximum number of source entries permitted in one listener policy.
pub const MAX_SOURCE_ENTRIES: usize = 64;

/// A relay configuration loaded from TOML and validated before use.
#[derive(Clone)]
pub struct RelayConfig {
    /// The local Herdr socket settings.
    relay: RelaySection,
    /// The network listener settings.
    network: NetworkConfig,
    /// The mandatory mutual-TLS settings.
    security: SecurityConfig,
    /// The fixed v1 resource limits.
    limits: ResourceLimits,
}

/// The private deserialization shape used to validate every external config.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayConfigWire {
    /// The local Herdr socket settings.
    relay: RelaySection,
    /// The network listener settings.
    #[serde(default = "default_network_config")]
    network: NetworkConfig,
    /// The mandatory mutual-TLS settings.
    security: SecurityConfig,
    /// The fixed v1 resource limits.
    #[serde(default)]
    limits: ResourceLimits,
}

impl<'de> Deserialize<'de> for RelayConfig {
    /// Deserializes and validates a relay configuration before exposing it.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RelayConfigWire::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl RelayConfig {
    /// Parses and validates one TOML configuration string.
    ///
    /// # Arguments
    ///
    /// * `input` - The complete UTF-8 TOML configuration.
    ///
    /// # Returns
    ///
    /// A validated configuration or a redacted configuration error.
    pub fn from_toml_str(input: &str) -> RelayResult<Self> {
        let wire: RelayConfigWire =
            toml::from_str(input).map_err(|_| RelayError::ConfigurationSyntax)?;
        Self::from_wire(wire)
    }

    /// Builds and validates a public configuration from its private wire shape.
    fn from_wire(wire: RelayConfigWire) -> RelayResult<Self> {
        let config = Self {
            relay: wire.relay,
            network: wire.network,
            security: wire.security,
            limits: wire.limits,
        };
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses, and validates a TOML configuration file.
    ///
    /// # Arguments
    ///
    /// * `path` - The configuration file path.
    ///
    /// # Returns
    ///
    /// A validated configuration or a redacted configuration error.
    pub fn from_path(path: &Path) -> RelayResult<Self> {
        let input = fs::read_to_string(path).map_err(|_| RelayError::ConfigurationRead)?;
        Self::from_toml_str(&input)
    }

    /// Revalidates the configuration before a listener or socket is opened.
    ///
    /// # Returns
    ///
    /// `Ok(())` when every boundary is valid, otherwise a redacted error.
    pub fn validate(&self) -> RelayResult<()> {
        validate_absolute_path("relay.herdr_socket", &self.relay.herdr_socket)?;
        self.network.validate()?;
        self.security.validate()?;
        self.limits.validate()
    }

    /// Returns the configured Herdr Unix socket path.
    ///
    /// # Returns
    ///
    /// The validated socket path.
    pub fn herdr_socket(&self) -> &Path {
        &self.relay.herdr_socket
    }

    /// Returns the validated network policy.
    ///
    /// # Returns
    ///
    /// The network configuration.
    pub fn network(&self) -> &NetworkConfig {
        &self.network
    }

    /// Returns the validated mutual-TLS configuration.
    ///
    /// # Returns
    ///
    /// The security configuration.
    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    /// Returns the validated resource limits.
    ///
    /// # Returns
    ///
    /// The v1 resource limits.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }
}

/// The local Herdr dependency configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySection {
    /// The configured Herdr Unix socket path.
    herdr_socket: PathBuf,
}

/// The three-class listener and fixed v1 port policy.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// The shared v1 listener base port.
    #[serde(default = "default_port_base")]
    port_base: u16,
    /// The shared v1 listener attempt count.
    #[serde(default = "default_port_attempts")]
    port_attempts: u8,
    /// The Tailscale listener policy.
    #[serde(default = "default_tailscale_listener")]
    tailscale: ListenerConfig,
    /// The LAN listener policy.
    #[serde(default)]
    lan: ListenerConfig,
    /// The public listener policy.
    #[serde(default)]
    public: ListenerConfig,
}

impl NetworkConfig {
    /// Returns the validated v1 base port.
    ///
    /// # Returns
    ///
    /// Always `18743` after validation.
    pub fn port_base(&self) -> u16 {
        self.port_base
    }

    /// Returns the validated v1 attempt count.
    ///
    /// # Returns
    ///
    /// Always `10` after validation.
    pub fn port_attempts(&self) -> u8 {
        self.port_attempts
    }

    /// Returns one listener policy by network class.
    ///
    /// # Arguments
    ///
    /// * `class` - The listener class to inspect.
    ///
    /// # Returns
    ///
    /// The corresponding listener policy.
    pub fn listener(&self, class: ListenerClass) -> &ListenerConfig {
        match class {
            ListenerClass::Tailscale => &self.tailscale,
            ListenerClass::Lan => &self.lan,
            ListenerClass::Public => &self.public,
        }
    }

    /// Iterates over every configured listener in stable class order.
    ///
    /// # Returns
    ///
    /// An iterator over class and policy pairs.
    pub fn listeners(&self) -> impl Iterator<Item = (ListenerClass, &ListenerConfig)> {
        [
            (ListenerClass::Tailscale, &self.tailscale),
            (ListenerClass::Lan, &self.lan),
            (ListenerClass::Public, &self.public),
        ]
        .into_iter()
    }

    /// Iterates over only enabled listener policies.
    ///
    /// # Returns
    ///
    /// An iterator over enabled class and policy pairs.
    pub fn enabled_listeners(&self) -> impl Iterator<Item = (ListenerClass, &ListenerConfig)> {
        self.listeners().filter(|(_, listener)| listener.enabled)
    }

    /// Validates the fixed v1 port policy and every class policy.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the network policy is fail-closed and valid.
    pub fn validate(&self) -> RelayResult<()> {
        if self.port_base != V1_PORT_BASE {
            return Err(RelayError::InvalidConfiguration {
                field: "network.port_base",
                reason: "must be the v1 value 18743",
            });
        }
        if self.port_attempts != V1_PORT_ATTEMPTS {
            return Err(RelayError::InvalidConfiguration {
                field: "network.port_attempts",
                reason: "must be the v1 value 10",
            });
        }
        for (class, listener) in self.listeners() {
            listener.validate(class)?;
        }
        Ok(())
    }
}

/// A network class selected by the accepted listener, never by request data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ListenerClass {
    /// The Tailscale listener.
    Tailscale,
    /// The explicitly enabled LAN listener.
    Lan,
    /// The explicitly approved public listener.
    Public,
}

impl ListenerClass {
    /// Returns all listener classes in stable configuration order.
    ///
    /// # Returns
    ///
    /// The Tailscale, LAN, and public classes.
    pub const fn all() -> [Self; 3] {
        [Self::Tailscale, Self::Lan, Self::Public]
    }

    /// Returns the stable lower-case diagnostic name.
    ///
    /// # Returns
    ///
    /// The non-secret class name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale",
            Self::Lan => "lan",
            Self::Public => "public",
        }
    }

    /// Returns the fixed handshake class code.
    ///
    /// # Returns
    ///
    /// `1`, `2`, or `3` for the three v1 classes.
    pub const fn code(self) -> u8 {
        match self {
            Self::Tailscale => 1,
            Self::Lan => 2,
            Self::Public => 3,
        }
    }
}

/// One explicitly configured network listener policy.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Whether this listener is enabled.
    #[serde(default)]
    enabled: bool,
    /// The explicit non-wildcard bind address.
    #[serde(default)]
    bind_address: Option<IpAddr>,
    /// The exact source address or CIDR allowlist.
    #[serde(default, deserialize_with = "deserialize_source_networks")]
    allowed_sources: Vec<IpNet>,
}

impl ListenerConfig {
    /// Returns whether the listener is enabled.
    ///
    /// # Returns
    ///
    /// `true` when this class may bind.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the explicit bind address, if configured.
    ///
    /// # Returns
    ///
    /// The bind address for an enabled listener.
    pub fn bind_address(&self) -> Option<IpAddr> {
        self.bind_address
    }

    /// Returns the configured source allowlist.
    ///
    /// # Returns
    ///
    /// A borrowed, validated list of source networks.
    pub fn allowed_sources(&self) -> &[IpNet] {
        &self.allowed_sources
    }

    /// Returns whether a peer address is admitted by this listener policy.
    ///
    /// # Arguments
    ///
    /// * `peer` - The source address reported by the accepted socket.
    ///
    /// # Returns
    ///
    /// `true` only when the listener is enabled and one allowlist entry contains the peer.
    pub fn allows(&self, peer: IpAddr) -> bool {
        self.enabled
            && self
                .allowed_sources
                .iter()
                .any(|network| network.contains(&peer))
    }

    /// Validates enabled-state, bind-address, and source-policy invariants.
    ///
    /// # Arguments
    ///
    /// * `class` - The owning listener class used for stable error labels.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the listener policy is explicit and fail-closed.
    pub fn validate(&self, class: ListenerClass) -> RelayResult<()> {
        let (enabled_field, address_field, sources_field) = match class {
            ListenerClass::Tailscale => (
                "network.tailscale.enabled",
                "network.tailscale.bind_address",
                "network.tailscale.allowed_sources",
            ),
            ListenerClass::Lan => (
                "network.lan.enabled",
                "network.lan.bind_address",
                "network.lan.allowed_sources",
            ),
            ListenerClass::Public => (
                "network.public.enabled",
                "network.public.bind_address",
                "network.public.allowed_sources",
            ),
        };

        if !self.enabled {
            if self.bind_address.is_some() || !self.allowed_sources.is_empty() {
                return Err(RelayError::InvalidConfiguration {
                    field: enabled_field,
                    reason: "disabled listeners must not define address or sources",
                });
            }
            return Ok(());
        }

        let Some(bind_address) = self.bind_address else {
            return Err(RelayError::InvalidConfiguration {
                field: address_field,
                reason: "enabled listeners require an explicit address",
            });
        };
        if bind_address.is_unspecified() {
            return Err(RelayError::InvalidConfiguration {
                field: address_field,
                reason: "wildcard addresses are not allowed",
            });
        }
        if bind_address.is_multicast() {
            return Err(RelayError::InvalidConfiguration {
                field: address_field,
                reason: "multicast addresses are not listener addresses",
            });
        }
        if self.allowed_sources.is_empty() {
            return Err(RelayError::InvalidConfiguration {
                field: sources_field,
                reason: "enabled listeners require a non-empty source allowlist",
            });
        }
        if self.allowed_sources.len() > MAX_SOURCE_ENTRIES {
            return Err(RelayError::InvalidConfiguration {
                field: sources_field,
                reason: "source allowlist is too large",
            });
        }
        for source in &self.allowed_sources {
            let source_network = source.network();
            if source_network.is_unspecified() {
                return Err(RelayError::InvalidConfiguration {
                    field: sources_field,
                    reason: "unspecified source networks are not allowed",
                });
            }
            if !same_address_family(bind_address, source_network) {
                return Err(RelayError::InvalidConfiguration {
                    field: sources_field,
                    reason: "source network family must match bind address",
                });
            }
        }
        Ok(())
    }
}

/// Mandatory mutual-TLS file and server identity configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// The authentication mode, which must be `mutual_tls` in v1.
    authentication: String,
    /// The relay server certificate chain path.
    server_cert: PathBuf,
    /// The relay server private-key path.
    server_key: PathBuf,
    /// The trusted client CA certificate path.
    trusted_client_ca: PathBuf,
    /// The expected server identity name.
    server_name: String,
}

impl SecurityConfig {
    /// Returns the server certificate path.
    ///
    /// # Returns
    ///
    /// The validated certificate path.
    pub fn server_cert(&self) -> &Path {
        &self.server_cert
    }

    /// Returns the server private-key path.
    ///
    /// # Returns
    ///
    /// The validated private-key path.
    pub fn server_key(&self) -> &Path {
        &self.server_key
    }

    /// Returns the trusted client CA path.
    ///
    /// # Returns
    ///
    /// The validated CA path.
    pub fn trusted_client_ca(&self) -> &Path {
        &self.trusted_client_ca
    }

    /// Returns the configured server identity name.
    ///
    /// # Returns
    ///
    /// The validated identity name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Validates mandatory mutual-TLS mode and non-secret path references.
    ///
    /// # Returns
    ///
    /// `Ok(())` when security configuration is complete.
    pub fn validate(&self) -> RelayResult<()> {
        if self.authentication != "mutual_tls" {
            return Err(RelayError::InvalidConfiguration {
                field: "security.authentication",
                reason: "v1 requires mutual_tls",
            });
        }
        validate_absolute_path("security.server_cert", &self.server_cert)?;
        validate_absolute_path("security.server_key", &self.server_key)?;
        validate_absolute_path("security.trusted_client_ca", &self.trusted_client_ca)?;
        if !valid_server_identity(&self.server_name) {
            return Err(RelayError::InvalidConfiguration {
                field: "security.server_name",
                reason: "must be a valid DNS name or IP address",
            });
        }
        Ok(())
    }
}

/// Fixed v1 connection, timeout, buffer, and diagnostic limits.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// The global concurrent client limit.
    #[serde(default = "default_max_clients")]
    max_clients: u16,
    /// The per-listener concurrent client limit.
    #[serde(default = "default_max_clients_per_listener")]
    max_clients_per_listener: u16,
    /// The concurrent unauthenticated handshake limit.
    #[serde(default = "default_max_handshakes")]
    max_handshakes: u16,
    /// The TLS and Relay handshake deadline in seconds.
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    /// The App probe deadline in seconds.
    #[serde(default = "default_probe_timeout_secs")]
    probe_timeout_secs: u64,
    /// The byte-stream idle timeout in seconds.
    #[serde(default = "default_idle_timeout_secs")]
    idle_timeout_secs: u64,
    /// The per-direction forwarding buffer size.
    #[serde(default = "default_buffer_bytes")]
    buffer_bytes: usize,
    /// The maximum diagnostic record size.
    #[serde(default = "default_max_diagnostic_bytes")]
    max_diagnostic_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_clients: V1_MAX_CLIENTS,
            max_clients_per_listener: V1_MAX_CLIENTS_PER_LISTENER,
            max_handshakes: V1_MAX_HANDSHAKES,
            handshake_timeout_secs: V1_HANDSHAKE_TIMEOUT_SECS,
            probe_timeout_secs: V1_PROBE_TIMEOUT_SECS,
            idle_timeout_secs: V1_IDLE_TIMEOUT_SECS,
            buffer_bytes: V1_BUFFER_BYTES,
            max_diagnostic_bytes: V1_MAX_DIAGNOSTIC_BYTES,
        }
    }
}

impl ResourceLimits {
    /// Returns the global client limit.
    pub fn max_clients(&self) -> u16 {
        self.max_clients
    }

    /// Returns the per-listener client limit.
    pub fn max_clients_per_listener(&self) -> u16 {
        self.max_clients_per_listener
    }

    /// Returns the concurrent handshake limit.
    pub fn max_handshakes(&self) -> u16 {
        self.max_handshakes
    }

    /// Returns the handshake timeout in seconds.
    pub fn handshake_timeout_secs(&self) -> u64 {
        self.handshake_timeout_secs
    }

    /// Returns the App probe timeout in seconds.
    pub fn probe_timeout_secs(&self) -> u64 {
        self.probe_timeout_secs
    }

    /// Returns the idle timeout in seconds.
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    /// Returns the per-direction buffer size.
    pub fn buffer_bytes(&self) -> usize {
        self.buffer_bytes
    }

    /// Returns the diagnostic record limit.
    pub fn max_diagnostic_bytes(&self) -> usize {
        self.max_diagnostic_bytes
    }

    /// Validates every fixed v1 resource value.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all limits match the documented v1 contract.
    pub fn validate(&self) -> RelayResult<()> {
        let checks = [
            (
                "limits.max_clients",
                self.max_clients == V1_MAX_CLIENTS,
                "must be the v1 value 64",
            ),
            (
                "limits.max_clients_per_listener",
                self.max_clients_per_listener == V1_MAX_CLIENTS_PER_LISTENER,
                "must be the v1 value 32",
            ),
            (
                "limits.max_handshakes",
                self.max_handshakes == V1_MAX_HANDSHAKES,
                "must be the v1 value 16",
            ),
            (
                "limits.handshake_timeout_secs",
                self.handshake_timeout_secs == V1_HANDSHAKE_TIMEOUT_SECS,
                "must be the v1 value 5",
            ),
            (
                "limits.probe_timeout_secs",
                self.probe_timeout_secs == V1_PROBE_TIMEOUT_SECS,
                "must be the v1 value 2",
            ),
            (
                "limits.idle_timeout_secs",
                self.idle_timeout_secs == V1_IDLE_TIMEOUT_SECS,
                "must be the v1 value 900",
            ),
            (
                "limits.buffer_bytes",
                self.buffer_bytes == V1_BUFFER_BYTES,
                "must be the v1 value 65536",
            ),
            (
                "limits.max_diagnostic_bytes",
                self.max_diagnostic_bytes == V1_MAX_DIAGNOSTIC_BYTES,
                "must be the v1 value 4096",
            ),
        ];
        for (field, valid, reason) in checks {
            if !valid {
                return Err(RelayError::InvalidConfiguration { field, reason });
            }
        }
        if self.max_clients_per_listener > self.max_clients {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.max_clients_per_listener",
                reason: "must not exceed the global client limit",
            });
        }
        Ok(())
    }
}

/// Checks that a path is an absolute, non-root configuration reference.
pub(crate) fn validate_absolute_path(field: &'static str, path: &Path) -> RelayResult<()> {
    let Some(path_text) = path.to_str() else {
        return Err(RelayError::InvalidConfiguration {
            field,
            reason: "must be valid UTF-8",
        });
    };
    if path_text.is_empty() || !path.is_absolute() || path == Path::new("/") {
        return Err(RelayError::InvalidConfiguration {
            field,
            reason: "must be a non-empty absolute path",
        });
    }
    if path_text
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Err(RelayError::InvalidConfiguration {
            field,
            reason: "must not contain relative path components",
        });
    }
    Ok(())
}

/// Checks that two addresses use the same IP family.
fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// Supplies the fail-closed default network policy before address validation.
fn default_network_config() -> NetworkConfig {
    NetworkConfig {
        port_base: V1_PORT_BASE,
        port_attempts: V1_PORT_ATTEMPTS,
        tailscale: default_tailscale_listener(),
        lan: ListenerConfig::default(),
        public: ListenerConfig::default(),
    }
}

/// Accepts either a single IP address or an explicit CIDR source entry.
fn deserialize_source_networks<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    let entries = Vec::<String>::deserialize(deserializer)?;
    entries
        .into_iter()
        .map(|entry| {
            if entry.contains('/') {
                let network = entry
                    .parse::<IpNet>()
                    .map_err(|_| D::Error::custom("invalid source network"))?;
                if network.network() != network.addr() {
                    return Err(D::Error::custom(
                        "source network must use canonical host bits",
                    ));
                }
                Ok(network)
            } else {
                let address = entry
                    .parse::<IpAddr>()
                    .map_err(|_| D::Error::custom("invalid source address"))?;
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                IpNet::new(address, prefix)
                    .map_err(|_| D::Error::custom("invalid source address prefix"))
            }
        })
        .collect()
}

/// Validates the DNS or IP grammar accepted for the TLS server identity.
fn valid_server_identity(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return false;
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return !address.is_unspecified() && !address.is_multicast();
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn default_port_base() -> u16 {
    V1_PORT_BASE
}

/// Supplies the fixed v1 attempt count to Serde.
fn default_port_attempts() -> u8 {
    V1_PORT_ATTEMPTS
}

/// Supplies the secure default Tailscale policy.
fn default_tailscale_listener() -> ListenerConfig {
    ListenerConfig {
        enabled: true,
        bind_address: None,
        allowed_sources: Vec::new(),
    }
}

/// Supplies the fixed global client limit to Serde.
fn default_max_clients() -> u16 {
    V1_MAX_CLIENTS
}

/// Supplies the fixed per-listener client limit to Serde.
fn default_max_clients_per_listener() -> u16 {
    V1_MAX_CLIENTS_PER_LISTENER
}

/// Supplies the fixed handshake limit to Serde.
fn default_max_handshakes() -> u16 {
    V1_MAX_HANDSHAKES
}

/// Supplies the fixed handshake timeout to Serde.
fn default_handshake_timeout_secs() -> u64 {
    V1_HANDSHAKE_TIMEOUT_SECS
}

/// Supplies the fixed probe timeout to Serde.
fn default_probe_timeout_secs() -> u64 {
    V1_PROBE_TIMEOUT_SECS
}

/// Supplies the fixed idle timeout to Serde.
fn default_idle_timeout_secs() -> u64 {
    V1_IDLE_TIMEOUT_SECS
}

/// Supplies the fixed forwarding buffer size to Serde.
fn default_buffer_bytes() -> usize {
    V1_BUFFER_BYTES
}

/// Supplies the fixed diagnostic limit to Serde.
fn default_max_diagnostic_bytes() -> usize {
    V1_MAX_DIAGNOSTIC_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[relay]
herdr_socket = "/Users/test/.config/herdr/herdr.sock"

[network]
port_base = 18743
port_attempts = 10

[network.tailscale]
enabled = true
bind_address = "127.0.0.1"
allowed_sources = ["127.0.0.1"]

[security]
authentication = "mutual_tls"
server_cert = "/Users/test/.config/herdr/relay-server.pem"
server_key = "/Users/test/.config/herdr/relay-server.key"
trusted_client_ca = "/Users/test/.config/herdr/relay-client-ca.pem"
server_name = "relay.test"
"#;

    // Test helper that preserves redaction by avoiding Debug formatting of valid configs.
    fn parse_error(input: &str) -> RelayError {
        match RelayConfig::from_toml_str(input) {
            Ok(_) => panic!("expected invalid configuration"),
            Err(error) => error,
        }
    }

    // TEST:relay/src/config.rs[tests::valid_configuration_exposes_only_v1_values]
    #[test]
    fn valid_configuration_exposes_only_v1_values() {
        let config = RelayConfig::from_toml_str(VALID_CONFIG).expect("valid configuration");
        assert_eq!(V1_PORT_LAST, 18_752);
        assert_eq!(config.network().port_base(), V1_PORT_BASE);
        assert_eq!(config.network().port_attempts(), V1_PORT_ATTEMPTS);
        assert_eq!(config.limits().max_clients(), V1_MAX_CLIENTS);
        assert_eq!(config.limits().buffer_bytes(), V1_BUFFER_BYTES);
        assert_eq!(
            config.network().enabled_listeners().count(),
            1,
            "only the default Tailscale class is enabled"
        );
        assert_eq!(
            config
                .network()
                .listener(ListenerClass::Tailscale)
                .bind_address(),
            Some("127.0.0.1".parse().expect("loopback address"))
        );
    }

    // TEST:relay/src/config.rs[tests::direct_deserialization_is_validated]
    #[test]
    fn direct_deserialization_is_validated() {
        let valid: RelayConfig =
            toml::from_str(VALID_CONFIG).expect("validated direct deserialization");
        assert_eq!(valid.network().port_base(), V1_PORT_BASE);
        let invalid = VALID_CONFIG.replace("port_base = 18743", "port_base = 18744");
        assert!(toml::from_str::<RelayConfig>(&invalid).is_err());
    }

    // TEST:relay/src/config.rs[tests::invalid_attempt_count_is_rejected]
    #[test]
    fn invalid_attempt_count_is_rejected() {
        let input = VALID_CONFIG.replace("port_attempts = 10", "port_attempts = 9");
        let error = parse_error(&input);
        assert!(error.to_string().contains("network.port_attempts"));
    }

    // TEST:relay/src/config.rs[tests::fixed_resource_override_is_rejected]
    #[test]
    fn fixed_resource_override_is_rejected() {
        let input = format!("{VALID_CONFIG}\n[limits]\nmax_clients = 63\n");
        let error = parse_error(&input);
        assert!(error.to_string().contains("limits.max_clients"));
    }

    // TEST:relay/src/config.rs[tests::unknown_fields_are_rejected]
    #[test]
    fn unknown_fields_are_rejected() {
        let input = VALID_CONFIG.replace("[network]\n", "[network]\nunexpected = true\n");
        let error = parse_error(&input);
        assert!(matches!(error, RelayError::ConfigurationSyntax));
    }

    // TEST:relay/src/config.rs[tests::invalid_port_is_rejected]
    #[test]
    fn invalid_port_is_rejected() {
        let input = VALID_CONFIG.replace("port_base = 18743", "port_base = 18744");
        let error = parse_error(&input);
        assert!(error.to_string().contains("network.port_base"));
    }

    // TEST:relay/src/config.rs[tests::ipv6_wildcard_bind_is_rejected]
    #[test]
    fn ipv6_wildcard_bind_is_rejected() {
        let input = VALID_CONFIG.replace("127.0.0.1", "::");
        let error = parse_error(&input);
        assert!(error.to_string().contains("wildcard addresses"));
    }

    // TEST:relay/src/config.rs[tests::multicast_bind_is_rejected]
    #[test]
    fn multicast_bind_is_rejected() {
        let input =
            VALID_CONFIG.replace("bind_address = \"127.0.0.1\"", "bind_address = \"ff02::1\"");
        let error = parse_error(&input);
        assert!(error.to_string().contains("multicast addresses"));
    }

    // TEST:relay/src/config.rs[tests::unspecified_source_is_rejected]
    #[test]
    fn unspecified_source_is_rejected() {
        let input = VALID_CONFIG.replace(
            "allowed_sources = [\"127.0.0.1\"]",
            "allowed_sources = [\"0.0.0.0/0\"]",
        );
        let error = parse_error(&input);
        assert!(error.to_string().contains("unspecified source"));
    }

    // TEST:relay/src/config.rs[tests::source_family_mismatch_is_rejected]
    #[test]
    fn source_family_mismatch_is_rejected() {
        let input = VALID_CONFIG.replace(
            "allowed_sources = [\"127.0.0.1\"]",
            "allowed_sources = [\"::1/128\"]",
        );
        let error = parse_error(&input);
        assert!(error.to_string().contains("source network family"));
    }

    // TEST:relay/src/config.rs[tests::cidr_and_bare_ipv6_sources_are_accepted]
    #[test]
    fn cidr_and_bare_ipv6_sources_are_accepted() {
        let input = VALID_CONFIG
            .replace("bind_address = \"127.0.0.1\"", "bind_address = \"::1\"")
            .replace(
                "allowed_sources = [\"127.0.0.1\"]",
                "allowed_sources = [\"::1\", \"::1/128\"]",
            );
        let config = RelayConfig::from_toml_str(&input).expect("valid IPv6 sources");
        let listener = config.network().listener(ListenerClass::Tailscale);
        assert_eq!(listener.allowed_sources().len(), 2);
        assert!(listener.allows("::1".parse().expect("IPv6 loopback")));
    }

    // TEST:relay/src/config.rs[tests::non_canonical_cidr_is_rejected]
    #[test]
    fn non_canonical_cidr_is_rejected() {
        let input = VALID_CONFIG.replace(
            "allowed_sources = [\"127.0.0.1\"]",
            "allowed_sources = [\"127.0.0.1/24\"]",
        );
        let error = parse_error(&input);
        assert!(matches!(error, RelayError::ConfigurationSyntax));
    }

    // TEST:relay/src/config.rs[tests::listener_admission_is_fail_closed]
    #[test]
    fn listener_admission_is_fail_closed() {
        let config = RelayConfig::from_toml_str(VALID_CONFIG).expect("valid configuration");
        let listener = config.network().listener(ListenerClass::Tailscale);
        assert!(listener.allows("127.0.0.1".parse().expect("IPv4 loopback")));
        assert!(!listener.allows("127.0.0.2".parse().expect("other IPv4 peer")));
        assert!(
            !config
                .network()
                .listener(ListenerClass::Lan)
                .allows("127.0.0.1".parse().expect("IPv4 loopback"))
        );
    }

    // TEST:relay/src/config.rs[tests::listener_class_codes_are_stable]
    #[test]
    fn listener_class_codes_are_stable() {
        assert_eq!(
            ListenerClass::all(),
            [
                ListenerClass::Tailscale,
                ListenerClass::Lan,
                ListenerClass::Public
            ]
        );
        assert_eq!(ListenerClass::Tailscale.as_str(), "tailscale");
        assert_eq!(ListenerClass::Lan.as_str(), "lan");
        assert_eq!(ListenerClass::Public.as_str(), "public");
        assert_eq!(ListenerClass::Tailscale.code(), 1);
        assert_eq!(ListenerClass::Lan.code(), 2);
        assert_eq!(ListenerClass::Public.code(), 3);
    }

    // TEST:relay/src/config.rs[tests::source_entry_limit_is_enforced]
    #[test]
    fn source_entry_limit_is_enforced() {
        let entries = std::iter::repeat_n("\"127.0.0.1\"", MAX_SOURCE_ENTRIES + 1)
            .collect::<Vec<_>>()
            .join(", ");
        let replacement = format!("allowed_sources = [{entries}]");
        let input = VALID_CONFIG.replace("allowed_sources = [\"127.0.0.1\"]", &replacement);
        let error = parse_error(&input);
        assert!(error.to_string().contains("source allowlist is too large"));
    }

    // TEST:relay/src/config.rs[tests::from_path_reads_and_validates]
    #[test]
    fn from_path_reads_and_validates() {
        let path = std::env::temp_dir().join(format!(
            "herdr-dog-relay-config-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, VALID_CONFIG).expect("write temporary configuration");
        let config = RelayConfig::from_path(&path).expect("read temporary configuration");
        std::fs::remove_file(&path).expect("remove temporary configuration");
        assert_eq!(config.network().port_base(), V1_PORT_BASE);
    }

    // TEST:relay/src/config.rs[tests::wildcard_bind_is_rejected]
    #[test]
    fn wildcard_bind_is_rejected() {
        let input =
            VALID_CONFIG.replace("bind_address = \"127.0.0.1\"", "bind_address = \"0.0.0.0\"");
        let error = parse_error(&input);
        assert!(error.to_string().contains("wildcard addresses"));
    }

    // TEST:relay/src/config.rs[tests::disabled_listener_cannot_retain_policy]
    #[test]
    fn disabled_listener_cannot_retain_policy() {
        let input = format!(
            "{VALID_CONFIG}\n[network.lan]\nenabled = false\nbind_address = \"127.0.0.1\"\n"
        );
        let error = parse_error(&input);
        assert!(error.to_string().contains("disabled listeners"));
    }

    // TEST:relay/src/config.rs[tests::mtls_file_references_reject_root]
    #[test]
    fn mtls_file_references_reject_root() {
        let input = VALID_CONFIG.replace(
            "server_cert = \"/Users/test/.config/herdr/relay-server.pem\"",
            "server_cert = \"/\"",
        );
        let error = parse_error(&input);
        assert!(error.to_string().contains("security.server_cert"));
        assert!(error.to_string().contains("absolute path"));
    }

    // TEST:relay/src/config.rs[tests::relative_path_components_are_rejected]
    #[test]
    fn relative_path_components_are_rejected() {
        for component in [".", ".."] {
            let input = VALID_CONFIG.replace(
                "/Users/test/.config/herdr/herdr.sock",
                &format!("/Users/test/.config/herdr/{component}/herdr.sock"),
            );
            let error = parse_error(&input);
            assert!(error.to_string().contains("relative path components"));
        }
    }

    // TEST:relay/src/config.rs[tests::invalid_server_identity_is_rejected]
    #[test]
    fn invalid_server_identity_is_rejected() {
        for identity in ["relay/name", "relay\\u0000.test"] {
            let input = VALID_CONFIG.replace(
                "server_name = \"relay.test\"",
                &format!("server_name = \"{identity}\""),
            );
            let error = parse_error(&input);
            assert!(error.to_string().contains("security.server_name"));
        }
    }

    // TEST:relay/src/config.rs[tests::weaker_authentication_is_rejected]
    #[test]
    fn weaker_authentication_is_rejected() {
        let input = VALID_CONFIG.replace(
            "authentication = \"mutual_tls\"",
            "authentication = \"server_tls\"",
        );
        let error = parse_error(&input);
        assert!(error.to_string().contains("mutual_tls"));
    }

    // TEST:relay/src/config.rs[tests::configuration_parser_redacts_input]
    #[test]
    fn configuration_parser_redacts_input() {
        let input =
            "[relay]\nherdr_socket = \"/Users/test/herdr.sock\"\nsecret = \"BEGIN PRIVATE KEY\"";
        let error = parse_error(input);
        assert!(!error.to_string().contains("BEGIN PRIVATE KEY"));
        assert!(!format!("{error:?}").contains("BEGIN PRIVATE KEY"));
    }

    // TEST:relay/src/config.rs[tests::default_network_is_fail_closed_until_address_is_supplied]
    #[test]
    fn default_network_is_fail_closed_until_address_is_supplied() {
        let input = r#"
[relay]
herdr_socket = "/Users/test/.config/herdr/herdr.sock"

[security]
authentication = "mutual_tls"
server_cert = "/Users/test/server.pem"
server_key = "/Users/test/server.key"
trusted_client_ca = "/Users/test/client-ca.pem"
server_name = "relay.test"
"#;
        let error = parse_error(input);
        assert!(error.to_string().contains("explicit address"));
    }
}
