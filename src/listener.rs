//! Authenticated Tailscale listener and bounded client admission.

use crate::{
    bridge::{self, BridgeLimits},
    config::{
        ListenerClass, ListenerConfig, RelayConfig, V1_HANDSHAKE_TIMEOUT_SECS, V1_PORT_ATTEMPTS,
        V1_PORT_BASE, V1_PORT_LAST, V1_PROBE_TIMEOUT_SECS, V1_RELAY_ALPN,
    },
    error::{RelayError, RelayResult},
    handshake::server_handshake,
    socket::UnixSocketConnector,
    tls::build_server_acceptor,
};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// The bounded reason recorded for the most recent client close or rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionCloseReason {
    /// Both directions reached EOF without an error.
    CleanEof,
    /// The peer source was outside the configured allowlist.
    SourceNotAllowed,
    /// The global client quota was exhausted.
    GlobalClientLimit,
    /// The Tailscale listener client quota was exhausted.
    ListenerClientLimit,
    /// The concurrent handshake quota was exhausted.
    HandshakeLimit,
    /// TLS client authentication failed.
    TlsAuthentication,
    /// The Relay binary handshake failed.
    RelayHandshake,
    /// The Relay handshake deadline elapsed.
    HandshakeTimeout,
    /// The configured Herdr Unix socket could not be opened.
    UpstreamUnavailable,
    /// The byte bridge reached its idle timeout.
    IdleTimeout,
    /// The listener stopped while the client task was still active.
    Cancelled,
    /// A bounded bridge or internal operation failed.
    Internal,
}

/// Bounded listener counters returned when a serving loop is stopped.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServeReport {
    /// Number of source-admitted client streams handed to a task.
    accepted: u64,
    /// Number of source or quota rejections made before task admission.
    rejected: u64,
    /// Number of client streams that completed with clean EOF.
    completed: u64,
    /// Number of admitted client streams that failed before clean EOF.
    failed: u64,
    /// Number of admitted client streams cancelled during listener shutdown.
    cancelled: u64,
    /// The total bytes forwarded toward the Herdr socket.
    network_to_unix_bytes: u64,
    /// The total bytes forwarded toward network clients.
    unix_to_network_bytes: u64,
    /// The most recent bounded close or rejection reason.
    last_close_reason: Option<ConnectionCloseReason>,
}

impl ServeReport {
    /// Returns the number of source-admitted streams.
    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Returns the number of source or quota rejections.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Returns the number of cleanly completed streams.
    pub fn completed(&self) -> u64 {
        self.completed
    }

    /// Returns the number of admitted streams that failed.
    pub fn failed(&self) -> u64 {
        self.failed
    }

    /// Returns the number of admitted streams cancelled during shutdown.
    pub fn cancelled(&self) -> u64 {
        self.cancelled
    }

    /// Returns the total bytes forwarded toward the Herdr socket.
    pub fn network_to_unix_bytes(&self) -> u64 {
        self.network_to_unix_bytes
    }

    /// Returns the total bytes forwarded toward network clients.
    pub fn unix_to_network_bytes(&self) -> u64 {
        self.unix_to_network_bytes
    }

    /// Returns the most recent bounded close or rejection reason.
    pub fn last_close_reason(&self) -> Option<ConnectionCloseReason> {
        self.last_close_reason
    }

    /// Records a pre-task rejection without retaining peer or payload data.
    fn record_rejection(&mut self, reason: ConnectionCloseReason) {
        self.rejected += 1;
        self.last_close_reason = Some(reason);
    }

    /// Records a completed or failed client task.
    fn record_task(&mut self, result: Result<RelayResult<ClientOutcome>, tokio::task::JoinError>) {
        match result {
            Ok(Ok(outcome)) => {
                self.completed += 1;
                self.network_to_unix_bytes += outcome.network_to_unix_bytes;
                self.unix_to_network_bytes += outcome.unix_to_network_bytes;
                self.last_close_reason = Some(outcome.reason);
            }
            Ok(Err(error)) => {
                self.failed += 1;
                self.last_close_reason = Some(close_reason_for_error(&error));
            }
            Err(error) if error.is_cancelled() => {
                self.cancelled += 1;
                self.last_close_reason = Some(ConnectionCloseReason::Cancelled);
            }
            Err(_) => {
                self.failed += 1;
                self.last_close_reason = Some(ConnectionCloseReason::Internal);
            }
        }
    }
}

/// The one-class authenticated listener delivered by the R3 milestone.
pub struct TailscaleListener {
    /// The selected TCP listener in the shared v1 candidate range.
    listener: TcpListener,
    /// The explicit Tailscale source policy.
    policy: ListenerConfig,
    /// The optional TLS 1.3 mutual-authentication acceptor.
    tls_acceptor: Option<TlsAcceptor>,
    /// The one configured Herdr Unix socket connector.
    connector: Arc<UnixSocketConnector>,
    /// The fixed bounded bridge policy.
    bridge_limits: BridgeLimits,
    /// The total handshake deadline.
    handshake_timeout: Duration,
    /// The bounded local-socket connection deadline.
    upstream_timeout: Duration,
    /// The global authenticated-client quota.
    global_clients: Arc<Semaphore>,
    /// The Tailscale listener client quota.
    listener_clients: Arc<Semaphore>,
    /// The concurrent TLS/Relay handshake quota.
    handshakes: Arc<Semaphore>,
    /// The listener class encoded into the handshake.
    class: ListenerClass,
}

impl TailscaleListener {
    /// Binds one authenticated Tailscale listener from validated configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The validated Relay configuration.
    /// * `expected_uid` - The Unix UID that must own the Herdr socket and parent.
    ///
    /// # Returns
    ///
    /// A listener bound to the first available v1 candidate, or a redacted startup error.
    pub async fn bind(config: &RelayConfig, expected_uid: u32) -> RelayResult<Self> {
        config.validate()?;
        if config
            .network()
            .listeners()
            .any(|(class, listener)| class != ListenerClass::Tailscale && listener.is_enabled())
        {
            return Err(RelayError::UnsupportedListenerClass);
        }
        if !config
            .network()
            .listener(ListenerClass::Tailscale)
            .is_enabled()
        {
            return Err(RelayError::ListenerStartup {
                reason: "the Tailscale listener is disabled",
            });
        }
        let tailscale_policy = config.network().listener(ListenerClass::Tailscale).clone();
        let bind_address = tailscale_policy
            .bind_address()
            .ok_or(RelayError::ListenerStartup {
                reason: "the Tailscale listener has no bind address",
            })?;
        let tls_acceptor = if tailscale_policy.uses_tls(ListenerClass::Tailscale) {
            let security = config.security().ok_or(RelayError::InvalidConfiguration {
                field: "security",
                reason: "TLS-enabled listeners require mutual-TLS settings",
            })?;
            Some(build_server_acceptor(security)?)
        } else {
            None
        };
        let bridge_limits = BridgeLimits::new(
            config.limits().buffer_bytes(),
            Duration::from_secs(config.limits().idle_timeout_secs()),
        )?;
        let connector = Arc::new(UnixSocketConnector::new(
            config.herdr_socket().to_path_buf(),
            expected_uid,
        )?);
        let listener = bind_first_available(bind_address).await?;
        Ok(Self {
            listener,
            policy: tailscale_policy,
            tls_acceptor,
            connector,
            bridge_limits,
            handshake_timeout: Duration::from_secs(
                config
                    .limits()
                    .handshake_timeout_secs()
                    .min(V1_HANDSHAKE_TIMEOUT_SECS),
            ),
            upstream_timeout: Duration::from_secs(
                config
                    .limits()
                    .probe_timeout_secs()
                    .min(V1_PROBE_TIMEOUT_SECS),
            ),
            global_clients: Arc::new(Semaphore::new(config.limits().max_clients() as usize)),
            listener_clients: Arc::new(Semaphore::new(
                config.limits().max_clients_per_listener() as usize
            )),
            handshakes: Arc::new(Semaphore::new(config.limits().max_handshakes() as usize)),
            class: ListenerClass::Tailscale,
        })
    }

    /// Returns the actual selected listener address.
    ///
    /// # Returns
    ///
    /// The explicit bind address and selected v1 port.
    pub fn local_addr(&self) -> RelayResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|error| RelayError::io("reading relay listener address", error))
    }

    /// Runs the accept loop until the caller's shutdown future resolves.
    ///
    /// Every spawned client task is owned by this loop and aborted before return on
    /// cancellation, so no forwarding task survives the listener owner.
    ///
    /// # Arguments
    ///
    /// * `shutdown` - A future that resolves when the listener should stop.
    ///
    /// # Returns
    ///
    /// Bounded connection counters after orderly shutdown, or a listener accept error.
    pub async fn serve_until<S>(self, shutdown: S) -> RelayResult<ServeReport>
    where
        S: Future<Output = ()> + Send + 'static,
    {
        let TailscaleListener {
            listener,
            policy,
            tls_acceptor,
            connector,
            bridge_limits,
            handshake_timeout,
            upstream_timeout,
            global_clients,
            listener_clients,
            handshakes,
            class,
        } = self;
        let mut shutdown = Box::pin(shutdown);
        let mut clients: JoinSet<RelayResult<ClientOutcome>> = JoinSet::new();
        let mut report = ServeReport::default();

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    clients.abort_all();
                    while let Some(result) = clients.join_next().await {
                        report.record_task(result);
                    }
                    return Ok(report);
                }
                joined = clients.join_next(), if !clients.is_empty() => {
                    if let Some(result) = joined {
                        report.record_task(result);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted
                        .map_err(|error| RelayError::io("accepting relay client", error))?;
                    if !policy.allows(peer.ip()) {
                        report.record_rejection(ConnectionCloseReason::SourceNotAllowed);
                        continue;
                    }
                    let Some(global_permit) = try_acquire(&global_clients) else {
                        report.record_rejection(ConnectionCloseReason::GlobalClientLimit);
                        continue;
                    };
                    let Some(listener_permit) = try_acquire(&listener_clients) else {
                        drop(global_permit);
                        report.record_rejection(ConnectionCloseReason::ListenerClientLimit);
                        continue;
                    };
                    let Some(handshake_permit) = try_acquire(&handshakes) else {
                        drop(listener_permit);
                        drop(global_permit);
                        report.record_rejection(ConnectionCloseReason::HandshakeLimit);
                        continue;
                    };
                    report.accepted += 1;
                    let context = ClientContext {
                        class,
                        tls_acceptor: tls_acceptor.clone(),
                        connector: connector.clone(),
                        bridge_limits,
                        handshake_timeout,
                        upstream_timeout,
                    };
                    let permits = ClientPermits {
                        _global: global_permit,
                        _listener: listener_permit,
                        handshake: handshake_permit,
                    };
                    clients.spawn(handle_client(stream, context, permits));
                }
            }
        }
    }
}

/// Binds the first available address in the immutable v1 candidate range.
async fn bind_first_available(bind_address: IpAddr) -> RelayResult<TcpListener> {
    debug_assert_eq!(V1_PORT_LAST, V1_PORT_BASE + u16::from(V1_PORT_ATTEMPTS) - 1);
    bind_candidates(bind_address, V1_PORT_BASE..=V1_PORT_LAST).await
}

/// Binds the first candidate in an ordered port iterator for deterministic tests and v1 startup.
async fn bind_candidates<I>(bind_address: IpAddr, candidates: I) -> RelayResult<TcpListener>
where
    I: IntoIterator<Item = u16>,
{
    for port in candidates {
        match TcpListener::bind(SocketAddr::new(bind_address, port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(_) => return Err(RelayError::ListenerAddressUnavailable),
        }
    }
    Err(RelayError::PortRangeExhausted)
}

/// Attempts one non-blocking quota acquisition.
fn try_acquire(semaphore: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    semaphore.clone().try_acquire_owned().ok()
}

/// The immutable per-client resources shared with one connection task.
struct ClientContext {
    /// The listener class encoded into the Relay handshake.
    class: ListenerClass,
    /// The optional TLS 1.3 mutual-authentication acceptor.
    tls_acceptor: Option<TlsAcceptor>,
    /// The configured Herdr Unix socket connector.
    connector: Arc<UnixSocketConnector>,
    /// The bounded byte-bridge policy.
    bridge_limits: BridgeLimits,
    /// The total TLS and Relay handshake deadline.
    handshake_timeout: Duration,
    /// The bounded Unix-socket connection deadline.
    upstream_timeout: Duration,
}

/// The quotas held for the entire lifetime of one admitted client task.
struct ClientPermits {
    /// The global client quota permit.
    _global: OwnedSemaphorePermit,
    /// The Tailscale listener quota permit.
    _listener: OwnedSemaphorePermit,
    /// The in-progress handshake quota permit.
    handshake: OwnedSemaphorePermit,
}

/// Handles one source-admitted client without retaining peer or payload data.
async fn handle_client(
    stream: TcpStream,
    context: ClientContext,
    permits: ClientPermits,
) -> RelayResult<ClientOutcome> {
    let ClientContext {
        class,
        tls_acceptor,
        connector,
        bridge_limits,
        handshake_timeout,
        upstream_timeout,
    } = context;
    let ClientPermits {
        _global,
        _listener,
        handshake,
    } = permits;
    let outcome = match tls_acceptor {
        Some(tls_acceptor) => {
            let tls = match time::timeout(
                handshake_timeout,
                authenticate_tls(stream, class, tls_acceptor),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => return Err(RelayError::RelayHandshakeTimeout),
            };
            drop(handshake);
            bridge_authenticated(tls, connector, upstream_timeout, bridge_limits).await?
        }
        None => {
            let plain =
                match time::timeout(handshake_timeout, authenticate_plain(stream, class)).await {
                    Ok(result) => result?,
                    Err(_) => return Err(RelayError::RelayHandshakeTimeout),
                };
            drop(handshake);
            bridge_authenticated(plain, connector, upstream_timeout, bridge_limits).await?
        }
    };
    Ok(ClientOutcome {
        reason: ConnectionCloseReason::CleanEof,
        network_to_unix_bytes: outcome.network_to_unix_bytes,
        unix_to_network_bytes: outcome.unix_to_network_bytes,
    })
}

/// Completes TLS and the binary Relay handshake before opening the Unix socket.
async fn authenticate_tls(
    stream: TcpStream,
    class: ListenerClass,
    tls_acceptor: TlsAcceptor,
) -> RelayResult<TlsStream<TcpStream>> {
    let mut tls = tls_acceptor
        .accept(stream)
        .await
        .map_err(|_| RelayError::TlsAuthentication)?;
    if tls.get_ref().1.alpn_protocol() != Some(V1_RELAY_ALPN) {
        return Err(RelayError::RelayHandshake);
    }
    server_handshake(&mut tls, class).await?;
    Ok(tls)
}

/// Completes the binary Relay handshake on a Tailscale-encrypted plain stream.
async fn authenticate_plain(mut stream: TcpStream, class: ListenerClass) -> RelayResult<TcpStream> {
    server_handshake(&mut stream, class).await?;
    Ok(stream)
}

/// Opens the validated Unix socket after the network authentication boundary succeeds.
async fn bridge_authenticated<S>(
    stream: S,
    connector: Arc<UnixSocketConnector>,
    upstream_timeout: Duration,
    bridge_limits: BridgeLimits,
) -> RelayResult<bridge::BridgeOutcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let unix = match time::timeout(upstream_timeout, connector.connect()).await {
        Ok(result) => result?,
        Err(_) => return Err(RelayError::UpstreamUnavailable),
    };
    bridge::run(stream, unix, bridge_limits).await
}

/// The internal result returned by one completed client task.
struct ClientOutcome {
    /// The bounded terminal reason.
    reason: ConnectionCloseReason,
    /// Bytes forwarded toward the Herdr socket.
    network_to_unix_bytes: u64,
    /// Bytes forwarded toward the network client.
    unix_to_network_bytes: u64,
}

/// Maps redacted operation errors to public close-reason categories.
fn close_reason_for_error(error: &RelayError) -> ConnectionCloseReason {
    match error {
        RelayError::SourceNotAllowed => ConnectionCloseReason::SourceNotAllowed,
        RelayError::ClientLimit => ConnectionCloseReason::GlobalClientLimit,
        RelayError::HandshakeLimit => ConnectionCloseReason::HandshakeLimit,
        RelayError::TlsAuthentication => ConnectionCloseReason::TlsAuthentication,
        RelayError::RelayHandshake => ConnectionCloseReason::RelayHandshake,
        RelayError::RelayHandshakeTimeout => ConnectionCloseReason::HandshakeTimeout,
        RelayError::UpstreamUnavailable | RelayError::SocketIdentity { .. } => {
            ConnectionCloseReason::UpstreamUnavailable
        }
        // Missing or refused socket connections are upstream availability, not listener internals.
        RelayError::Io { operation, kind }
            if matches!(
                *kind,
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) && matches!(
                *operation,
                "checking Herdr Unix socket"
                    | "checking Herdr socket parent"
                    | "checking Herdr socket path"
                    | "connecting to Herdr Unix socket"
            ) =>
        {
            ConnectionCloseReason::UpstreamUnavailable
        }
        RelayError::BridgeIdleTimeout => ConnectionCloseReason::IdleTimeout,
        RelayError::Io { .. } => ConnectionCloseReason::Internal,
        _ => ConnectionCloseReason::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{V1_MAX_CLIENTS_PER_LISTENER, V1_MAX_HANDSHAKES},
        handshake::client_handshake,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
        sync::oneshot,
    };
    use tokio_rustls::TlsConnector;

    /// A disposable certificate and configuration directory for listener tests.
    struct TestMaterial {
        /// The private temporary directory.
        root: PathBuf,
        /// The generated root CA certificate in PEM form.
        ca_pem: String,
        /// The generated server certificate and key paths.
        server_cert: PathBuf,
        /// The generated client certificate and key paths.
        client_cert: PathBuf,
        /// The generated root CA path.
        client_ca: PathBuf,
        /// The generated server key path.
        server_key: PathBuf,
    }

    impl TestMaterial {
        /// Generates ephemeral CA, server, and client certificates for one test.
        fn new() -> Self {
            let root = test_directory_path("tls");
            let ca_key = KeyPair::generate().expect("generate CA key");
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca_cert = ca_params
                .self_signed(&ca_key)
                .expect("self-sign CA certificate");
            let issuer = Issuer::new(ca_params, ca_key);

            let server_key = KeyPair::generate().expect("generate server key");
            let mut server_params = CertificateParams::new(vec!["relay.test".to_string()])
                .expect("server certificate parameters");
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_cert = server_params
                .signed_by(&server_key, &issuer)
                .expect("sign server certificate");

            let client_key = KeyPair::generate().expect("generate client key");
            let mut client_params = CertificateParams::new(vec!["client.test".to_string()])
                .expect("client certificate parameters");
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client_cert = client_params
                .signed_by(&client_key, &issuer)
                .expect("sign client certificate");

            let server_cert_path = root.join("server.pem");
            let server_key_path = root.join("server.key");
            let client_cert_path = root.join("client.pem");
            let client_key_path = root.join("client.key");
            let ca_path = root.join("ca.pem");
            write_file(&server_cert_path, server_cert.pem());
            write_file(&server_key_path, server_key.serialize_pem());
            write_file(&client_cert_path, client_cert.pem());
            write_file(&client_key_path, client_key.serialize_pem());
            write_file(&ca_path, ca_cert.pem());
            Self {
                root,
                ca_pem: ca_cert.pem(),
                server_cert: server_cert_path,
                client_cert: client_cert_path,
                client_ca: ca_path,
                server_key: server_key_path,
            }
        }

        /// Creates a valid Tailscale-only configuration for the supplied socket.
        fn config(&self, socket: &Path, source: &str) -> RelayConfig {
            self.config_with_tls(socket, source, true)
        }

        /// Creates a valid Tailscale-only configuration with explicit transport mode.
        fn config_with_tls(&self, socket: &Path, source: &str, tls: bool) -> RelayConfig {
            let input = format!(
                "[relay]\nherdr_socket = \"{}\"\n\n[network]\n\n[network.tailscale]\nenabled = true\ntls = {tls}\nbind_address = \"127.0.0.1\"\nallowed_sources = [\"{source}\"]\n\n[security]\nauthentication = \"mutual_tls\"\nserver_cert = \"{}\"\nserver_key = \"{}\"\ntrusted_client_ca = \"{}\"\nserver_name = \"relay.test\"\n",
                socket.display(),
                self.server_cert.display(),
                self.server_key.display(),
                self.client_ca.display(),
            );
            RelayConfig::from_toml_str(&input).expect("valid test listener configuration")
        }
    }

    impl Drop for TestMaterial {
        /// Removes generated certificate files after the test ends.
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Writes a disposable private test file with restrictive permissions.
    fn write_file(path: &Path, contents: impl AsRef<[u8]>) {
        let mut file = fs::File::create(path).expect("create test certificate file");
        file.write_all(contents.as_ref())
            .expect("write test certificate file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set test certificate file mode");
    }

    /// Creates a short private temporary directory suitable for Unix sockets.
    fn test_directory_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let base = fs::canonicalize("/tmp").expect("canonicalize short temporary directory");
        for attempt in 0..100_u16 {
            let root = base.join(format!(
                "hd-l-{label}-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .expect("set listener test directory mode");
                    return root;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create listener test directory: {error}"),
            }
        }
        panic!("could not allocate a unique listener test directory");
    }

    /// Creates a private Unix listener and returns its owner UID.
    fn private_unix_listener(path: &Path) -> (UnixListener, u32) {
        let listener = UnixListener::bind(path).expect("bind Herdr test socket");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set Herdr test socket mode");
        let uid = fs::symlink_metadata(path.parent().expect("socket parent"))
            .expect("read socket parent")
            .uid();
        (listener, uid)
    }

    /// Builds a mutual-TLS client configuration for an ephemeral test CA.
    fn client_config(material: &TestMaterial, with_client_auth: bool) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        let mut root_reader =
            std::io::BufReader::new(std::io::Cursor::new(material.ca_pem.as_bytes()));
        for certificate in rustls_pemfile::certs(&mut root_reader) {
            root_store
                .add(certificate.expect("parse test CA"))
                .expect("add test CA");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 client configuration");
        let mut config = if with_client_auth {
            let cert_bytes = fs::read(&material.client_cert).expect("read client certificate");
            let key_bytes = fs::read(material.root.join("client.key")).expect("read client key");
            let mut cert_reader = std::io::BufReader::new(std::io::Cursor::new(cert_bytes));
            let certificates = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .expect("parse client certificate");
            let mut key_reader = std::io::BufReader::new(std::io::Cursor::new(key_bytes));
            let key = rustls_pemfile::private_key(&mut key_reader)
                .expect("parse client key")
                .expect("client key exists");
            builder
                .with_root_certificates(root_store)
                .with_client_auth_cert(certificates, key)
                .expect("build authenticated client")
        } else {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        config.alpn_protocols = vec![crate::config::V1_RELAY_ALPN.to_vec()];
        config
    }

    /// Creates a TLS connector that validates the generated relay identity.
    fn tls_connector(material: &TestMaterial, with_client_auth: bool) -> TlsConnector {
        TlsConnector::from(Arc::new(client_config(material, with_client_auth)))
    }

    // TEST:relay/src/listener.rs[tests::bind_candidates_skip_occupied_ports]
    #[tokio::test(flavor = "current_thread")]
    async fn bind_candidates_skip_occupied_ports() {
        let blocker = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind occupied candidate");
        let occupied = blocker.local_addr().expect("read occupied port").port();
        let selected = bind_candidates("127.0.0.1".parse().expect("loopback"), [occupied, 0])
            .await
            .expect("bind second candidate");
        assert_ne!(
            selected.local_addr().expect("read selected port").port(),
            occupied
        );
    }

    // TEST:relay/src/listener.rs[tests::all_occupied_candidates_are_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn all_occupied_candidates_are_rejected() {
        let blocker = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind occupied candidate");
        let occupied = blocker.local_addr().expect("read occupied port").port();
        let error = bind_candidates("127.0.0.1".parse().expect("loopback"), [occupied])
            .await
            .expect_err("occupied candidate must exhaust range");
        assert!(matches!(error, RelayError::PortRangeExhausted));
    }

    // TEST:relay/src/listener.rs[tests::authenticated_client_reaches_one_unix_socket]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_client_reaches_one_unix_socket() {
        let root = test_directory_path("socket");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        let material = TestMaterial::new();
        let direct_connector =
            UnixSocketConnector::new(&socket_path, uid).expect("create direct connector");
        direct_connector
            .validate()
            .expect("validate test Herdr socket");
        let config = material.config(&socket_path, "127.0.0.1");
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind authenticated listener");
        let address = listener.local_addr().expect("listener address");
        assert!((V1_PORT_BASE..=V1_PORT_LAST).contains(&address.port()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (request_tx, request_rx) = oneshot::channel();
        let unix_server = tokio::spawn(async move {
            let (mut stream, _) = unix_listener.accept().await.expect("accept Herdr stream");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"ping");
            let _ = request_tx.send(());
            stream.write_all(b"pong").await.expect("write response");
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof).await.expect("read Core EOF"), 0);
            stream.shutdown().await.expect("close Herdr stream");
        });
        let tcp = TcpStream::connect(address).await.expect("connect listener");
        let connector = tls_connector(&material, true);
        let server_name =
            rustls::pki_types::ServerName::try_from("relay.test").expect("server name");
        let mut client = connector
            .connect(server_name, tcp)
            .await
            .expect("complete TLS client authentication");
        client_handshake(&mut client, ListenerClass::Tailscale)
            .await
            .expect("complete Relay handshake");
        client.write_all(b"ping").await.expect("write Core ping");
        if tokio::time::timeout(Duration::from_secs(1), request_rx)
            .await
            .is_err()
        {
            let _ = shutdown_tx.send(());
            let report = server
                .await
                .expect("join relay server")
                .expect("stop relay server");
            panic!("Herdr request was not forwarded: {report:?}");
        }
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("read Core pong");
        assert_eq!(&response, b"pong");
        client.shutdown().await.expect("close Core write half");
        unix_server.await.expect("join Herdr server");
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join relay server")
            .expect("stop relay server");
        assert_eq!(report.accepted(), 1);
        assert_eq!(report.completed(), 1);
        assert_eq!(
            report.last_close_reason(),
            Some(ConnectionCloseReason::CleanEof)
        );
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }

    // TEST:relay/src/listener.rs[tests::plain_client_reaches_one_unix_socket]
    #[tokio::test(flavor = "current_thread")]
    async fn plain_client_reaches_one_unix_socket() {
        let root = test_directory_path("plain");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        let material = TestMaterial::new();
        let direct_connector =
            UnixSocketConnector::new(&socket_path, uid).expect("create direct connector");
        direct_connector
            .validate()
            .expect("validate test Herdr socket");
        let config = material.config_with_tls(&socket_path, "127.0.0.1", false);
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind plain listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (request_tx, request_rx) = oneshot::channel();
        let unix_server = tokio::spawn(async move {
            let (mut stream, _) = unix_listener.accept().await.expect("accept Herdr stream");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"ping");
            let _ = request_tx.send(());
            stream.write_all(b"pong").await.expect("write response");
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof).await.expect("read Core EOF"), 0);
            stream.shutdown().await.expect("close Herdr stream");
        });
        let mut client = TcpStream::connect(address).await.expect("connect listener");
        client_handshake(&mut client, ListenerClass::Tailscale)
            .await
            .expect("complete plain Relay handshake");
        client.write_all(b"ping").await.expect("write Core ping");
        tokio::time::timeout(Duration::from_secs(1), request_rx)
            .await
            .expect("Herdr request timeout")
            .expect("Herdr request channel");
        let mut response = [0_u8; 4];
        client
            .read_exact(&mut response)
            .await
            .expect("read Core pong");
        assert_eq!(&response, b"pong");
        client.shutdown().await.expect("close Core write half");
        unix_server.await.expect("join Herdr server");
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join relay server")
            .expect("stop relay server");
        assert_eq!(report.accepted(), 1);
        assert_eq!(report.completed(), 1);
        assert_eq!(
            report.last_close_reason(),
            Some(ConnectionCloseReason::CleanEof)
        );
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }

    // TEST:relay/src/listener.rs[tests::missing_upstream_socket_is_rejected_before_forwarding]
    #[tokio::test(flavor = "current_thread")]
    async fn missing_upstream_socket_is_rejected_before_forwarding() {
        let root = test_directory_path("missing");
        let socket_path = root.join("herdr.sock");
        let material = TestMaterial::new();
        let config = material.config_with_tls(&socket_path, "127.0.0.1", false);
        let expected_uid = fs::symlink_metadata(&root)
            .expect("read missing socket parent")
            .uid();
        let listener = TailscaleListener::bind(&config, expected_uid)
            .await
            .expect("bind missing-socket listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));

        let mut client = TcpStream::connect(address).await.expect("connect listener");
        client_handshake(&mut client, ListenerClass::Tailscale)
            .await
            .expect("complete Relay handshake before upstream validation");
        let mut eof = [0_u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), client.read(&mut eof))
            .await
            .expect("missing socket close timeout")
            .expect("read missing socket close");
        assert_eq!(
            result, 0,
            "Relay must close without forwarding to a missing socket"
        );

        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join missing-socket relay")
            .expect("stop missing-socket relay");
        assert_eq!(report.accepted(), 1);
        assert_eq!(report.completed(), 0);
        assert_eq!(report.failed(), 1);
        assert_eq!(
            report.last_close_reason(),
            Some(ConnectionCloseReason::UpstreamUnavailable)
        );
        fs::remove_dir(root).expect("remove missing socket directory");
    }

    // TEST:relay/src/listener.rs[tests::listener_client_quota_rejects_excess_clients]
    #[tokio::test(flavor = "current_thread")]
    async fn listener_client_quota_rejects_excess_clients() {
        let root = test_directory_path("quota");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        let material = TestMaterial::new();
        let config = material.config_with_tls(&socket_path, "127.0.0.1", false);
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind quota listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (release_tx, release_rx) = oneshot::channel();
        let unix_server = tokio::spawn(async move {
            let mut streams = Vec::new();
            for _ in 0..V1_MAX_CLIENTS_PER_LISTENER {
                let (stream, _) = unix_listener.accept().await.expect("accept Herdr stream");
                streams.push(stream);
            }
            let _ = release_rx.await;
            streams
        });
        let mut clients = Vec::new();
        for _ in 0..V1_MAX_CLIENTS_PER_LISTENER {
            let mut client = TcpStream::connect(address)
                .await
                .expect("connect quota client");
            client_handshake(&mut client, ListenerClass::Tailscale)
                .await
                .expect("complete quota client handshake");
            clients.push(client);
            tokio::task::yield_now().await;
        }
        clients.push(
            TcpStream::connect(address)
                .await
                .expect("connect excess quota client"),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join quota relay server")
            .expect("stop quota relay server");
        assert_eq!(report.accepted(), u64::from(V1_MAX_CLIENTS_PER_LISTENER));
        assert!(report.rejected() >= 1, "the excess client must be rejected");
        assert!(report.cancelled() >= u64::from(V1_MAX_CLIENTS_PER_LISTENER));
        drop(clients);
        let _ = release_tx.send(());
        unix_server.await.expect("join Herdr quota server");
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }

    // TEST:relay/src/listener.rs[tests::handshake_quota_rejects_excess_clients]
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_quota_rejects_excess_clients() {
        let root = test_directory_path("handshake");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        let material = TestMaterial::new();
        let config = material.config_with_tls(&socket_path, "127.0.0.1", false);
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind handshake quota listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let mut clients = Vec::new();
        for _ in 0..=V1_MAX_HANDSHAKES {
            clients.push(
                TcpStream::connect(address)
                    .await
                    .expect("connect handshake quota client"),
            );
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join handshake quota server")
            .expect("stop handshake quota server");
        assert_eq!(report.accepted(), u64::from(V1_MAX_HANDSHAKES));
        assert!(
            report.rejected() >= 1,
            "the excess handshake must be rejected"
        );
        assert!(report.cancelled() >= u64::from(V1_MAX_HANDSHAKES));
        drop(clients);
        drop(unix_listener);
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }

    // TEST:relay/src/listener.rs[tests::unavailable_listener_address_is_distinct]
    #[tokio::test(flavor = "current_thread")]
    async fn unavailable_listener_address_is_distinct() {
        let error = bind_candidates("192.0.2.1".parse().expect("documentation address"), [0])
            .await
            .expect_err("unavailable address must not be treated as port exhaustion");
        assert!(matches!(error, RelayError::ListenerAddressUnavailable));
    }

    // TEST:relay/src/listener.rs[tests::client_without_certificate_cannot_reach_unix_socket]
    #[tokio::test(flavor = "current_thread")]
    async fn client_without_certificate_cannot_reach_unix_socket() {
        let root = test_directory_path("auth");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        drop(unix_listener);
        let material = TestMaterial::new();
        let config = material.config(&socket_path, "127.0.0.1");
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind authentication listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let tcp = TcpStream::connect(address).await.expect("connect listener");
        let connector = tls_connector(&material, false);
        let server_name =
            rustls::pki_types::ServerName::try_from("relay.test").expect("server name");
        let authentication_result = match connector.connect(server_name, tcp).await {
            Ok(mut client) => tokio::time::timeout(
                Duration::from_secs(1),
                client_handshake(&mut client, ListenerClass::Tailscale),
            )
            .await
            .map_err(|_| RelayError::RelayHandshakeTimeout)
            .and_then(|result| result),
            Err(error) => Err(RelayError::io("TLS client test", error)),
        };
        assert!(authentication_result.is_err());
        tokio::task::yield_now().await;
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join relay server")
            .expect("stop relay server");
        assert_eq!(report.accepted(), 1);
        assert_eq!(report.completed(), 0);
        assert_eq!(
            report.last_close_reason(),
            Some(ConnectionCloseReason::TlsAuthentication)
        );
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }

    // TEST:relay/src/listener.rs[tests::disallowed_source_is_rejected_before_tls]
    #[tokio::test(flavor = "current_thread")]
    async fn disallowed_source_is_rejected_before_tls() {
        let root = test_directory_path("source");
        let socket_path = root.join("herdr.sock");
        let (unix_listener, uid) = private_unix_listener(&socket_path);
        drop(unix_listener);
        let material = TestMaterial::new();
        let config = material.config(&socket_path, "127.0.0.2");
        let listener = TailscaleListener::bind(&config, uid)
            .await
            .expect("bind source-policy listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(listener.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let mut tcp = TcpStream::connect(address).await.expect("connect listener");
        tcp.write_all(b"not TLS").await.expect("write source probe");
        let mut eof = [0_u8; 1];
        match tcp.read(&mut eof).await {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            result => panic!("unexpected source rejection result: {result:?}"),
        }
        let _ = shutdown_tx.send(());
        let report = server
            .await
            .expect("join relay server")
            .expect("stop relay server");
        assert_eq!(report.accepted(), 0);
        assert_eq!(report.rejected(), 1);
        assert_eq!(
            report.last_close_reason(),
            Some(ConnectionCloseReason::SourceNotAllowed)
        );
        fs::remove_file(socket_path).expect("remove Herdr test socket");
        fs::remove_dir(root).expect("remove Herdr socket directory");
    }
}
