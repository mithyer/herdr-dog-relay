//! Production QRM-1 QUIC TLS 1.3 Relay server.
//!
//! The server owns one UDP listener per device, one HDQM control stream per connection and one
//! HDQS stream per approved session. Relay never parses or logs Herdr payload bytes.

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

use crate::{
    allowlist::PersistentAllowlist,
    bootstrap_runtime::{BOOTSTRAP_HARD_LIFETIME_SECS, BootstrapRuntime, BootstrapRuntimeError},
    bridge::{self, BridgeLimits},
    config::{QRM_HANDSHAKE_TIMEOUT_SECS, RelayConfig, SecurityMode},
    enrollment::{AllowlistState, Fingerprint, STABLE_LATEST_SELECTOR},
    error::{RelayError, RelayResult},
    issuance::{
        IssuanceBeginResult, IssuanceResultKey, IssuanceResultStatus, PersistentIssuanceResults,
    },
    material::{
        MAX_PRIVATE_MATERIAL_BYTES, MAX_PUBLIC_MATERIAL_BYTES, ProtectedFileKind, current_uid,
        read_protected_file,
    },
    pki::current_epoch_seconds,
    quic_wire::{
        DeviceHelloAck, HdqmFrame, HdqmKind, HdqsBinding, HdqsReason, HdqsResponse, SessionOpenAck,
        SessionOpenRequest, SessionPrepareAck, SessionPrepareRequest,
    },
    session_registry::SessionRegistry,
    socket::UnixSocketConnector,
    updater::FixedSourceUpdater,
};

#[cfg(test)]
use crate::{
    enrollment::{
        AppId, CoreAuthorization, CsrDigest, CsrMetadata, EnrollmentChallenge, EnrollmentSubmission,
    },
    enrollment_wire::{
        EnrollmentChallengePayload, EnrollmentFrame, EnrollmentFrameKind, EnrollmentIssuedPayload,
        EnrollmentRejectedPayload, EnrollmentSubmitPayload, EnrollmentWireError,
        write_frame as write_enrollment_frame,
    },
    pki::issue_certificate,
    reconciliation_wire::{
        RECONCILIATION_HEADER_BYTES, RECONCILIATION_MAGIC, RECONCILIATION_VERSION,
        ReconcilePayload, ReconciliationFrame, ReconciliationFrameKind,
        ReconciliationResultPayload, ReconciliationStatus,
        write_frame as write_reconciliation_frame,
    },
};

/// ALPN selected by every QRM-1 Relay connection.
pub const QRM_RELAY_ALPN: &[u8] = b"herdr-dog-relay-quic/1";
/// ALPN selected by the terminal App enrollment path.
pub const QRM_ENROLLMENT_ALPN: &[u8] = b"herdr-dog-relay-enroll/1";
/// ALPN selected by the server-authenticated first Core bootstrap path.
pub const QRM_BOOTSTRAP_ALPN: &[u8] = b"herdr-dog-relay-bootstrap/1";
/// Maximum time allowed for the initial control stream and session bind.
pub const QRM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(QRM_HANDSHAKE_TIMEOUT_SECS);
/// Maximum time allowed for an existing QUIC connection to drain after GOAWAY.
pub const QRM_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// AsyncRead/AsyncWrite adapter that combines one QUIC bidirectional stream.
struct QuicBiStream {
    /// QUIC receive half used by the bridge reader.
    recv: quinn::RecvStream,
    /// QUIC send half used by the bridge writer.
    send: quinn::SendStream,
}

impl AsyncRead for QuicBiStream {
    /// Polls bytes from the QUIC receive half.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for QuicBiStream {
    /// Polls bytes into the QUIC send half.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, bytes) {
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "QUIC send stream write failed",
            ))),
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Flushes the QUIC send half.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "QUIC send stream flush failed",
            ))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Finishes the QUIC send half.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "QUIC send stream shutdown failed",
            ))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Historical HDE1/HDE2 fixture helper; production dispatch uses HDB1/HDE3 only.
#[cfg(test)]
#[allow(dead_code)]
enum EnrollmentRequestFrame {
    /// Existing HDE1 Challenge/Submit/Issued/Rejected namespace.
    V1(EnrollmentFrame),
    /// HDE version-two response-lost reconciliation namespace.
    V2(ReconciliationFrame),
}

/// Historical HDE1/HDE2 fixture reader; production dispatch uses HDB1/HDE3 only.
#[cfg(test)]
#[allow(dead_code)]
async fn read_versioned_enrollment_frame(
    reader: &mut quinn::RecvStream,
    max_bytes: usize,
) -> RelayResult<EnrollmentRequestFrame> {
    let mut header = [0_u8; RECONCILIATION_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "enrollment frame header is invalid",
        })?;
    let payload_len = u32::from_be_bytes([header[7], header[8], header[9], header[10]]) as usize;
    if payload_len > max_bytes {
        return Err(RelayError::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(RECONCILIATION_HEADER_BYTES + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "enrollment frame payload is invalid",
        })?;
    bytes.extend_from_slice(&payload);
    if header[..4] != RECONCILIATION_MAGIC {
        return Err(RelayError::QuicProtocol {
            reason: "enrollment frame magic is invalid",
        });
    }
    match u16::from_be_bytes([header[4], header[5]]) {
        1 => EnrollmentFrame::decode(&bytes, max_bytes)
            .map(EnrollmentRequestFrame::V1)
            .map_err(|_| RelayError::QuicProtocol {
                reason: "HDE1 enrollment frame is invalid",
            }),
        RECONCILIATION_VERSION => ReconciliationFrame::decode(&bytes, max_bytes)
            .map(EnrollmentRequestFrame::V2)
            .map_err(|_| RelayError::QuicProtocol {
                reason: "HDE2 reconciliation frame is invalid",
            }),
        _ => Err(RelayError::QuicProtocol {
            reason: "enrollment frame version is unsupported",
        }),
    }
}

struct SessionTaskControl {
    /// One-shot cancellation authority for the exact session stream.
    cancel: oneshot::Sender<()>,
    /// Completion notification sent after bridge resources are dropped.
    done: Arc<Notify>,
}

type SessionTaskControls = Arc<Mutex<BTreeMap<u16, SessionTaskControl>>>;

/// One production QUIC Relay server owner.
pub struct QuicRelayServer {
    /// Validated one-listener configuration.
    config: RelayConfig,
    /// Relay process startup generation.
    relay_generation: u64,
    /// Relay certificate fingerprint repeated in the application hello.
    relay_identity: [u8; 32],
    /// Protected trust-bundle generation repeated in the application hello.
    ca_generation: u64,
    /// Bound Quinn endpoint, absent for the contract-only constructor.
    endpoint: Option<quinn::Endpoint>,
    /// Global connection quota.
    connections: Arc<Semaphore>,
    /// Independent bounded TLS handshakes before ALPN dispatch.
    pre_auth_handshakes: Arc<Semaphore>,
    /// Independent post-ALPN bootstrap handshake budget.
    bootstrap_handshakes: Arc<Semaphore>,
    /// Independent post-ALPN bootstrap connection budget.
    bootstrap_connections: Arc<Semaphore>,
    /// Independent pre-authentication enrollment budget.
    enrollment_handshakes: Arc<Semaphore>,
    /// Independent post-ALPN enrollment connection budget.
    enrollment_connections: Arc<Semaphore>,
    /// Protected durable issuance-result store used for response-lost reconciliation.
    issuance_results: Option<Arc<Mutex<crate::issuance::PersistentIssuanceResults>>>,
    /// Protected App allowlist required by every bound verified-QRM server.
    ///
    /// Contract-only and test-only unverified owners retain `None` because they never expose
    /// production normal-QRM admission.
    allowlist: Option<Arc<Mutex<PersistentAllowlist>>>,
    /// Broadcasts the bounded drain deadline to every accepted connection task.
    drain_tx: watch::Sender<Option<Instant>>,
    /// Core bootstrap and later-App approval authority shared by connections.
    bootstrap: Option<Arc<BootstrapRuntime>>,

    /// Optional test-only socket override for deterministic Unix bridge tests.
    socket_override: Option<PathBuf>,
}

impl std::fmt::Debug for QuicRelayServer {
    /// Reports only non-secret listener and generation metadata.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicRelayServer")
            .field("relay_generation_present", &true)
            .field("relay_identity_present", &true)
            .field("ca_generation_present", &true)
            .field("bound", &self.endpoint.is_some())
            .field("connection_limit", &self.config.limits().max_connections())
            .finish()
    }
}

impl QuicRelayServer {
    /// Creates a contract-only server owner after validating configuration.
    ///
    /// # Parameters
    /// * `config` - Validated one-listener QRM configuration.
    /// * `relay_generation` - Non-zero process startup epoch.
    ///
    /// # Returns
    /// A server owner that has not opened a UDP socket.
    // TEST:relay/src/quic_server.rs[tests::server_accepts_only_valid_generation]
    pub fn new(config: RelayConfig, relay_generation: u64) -> RelayResult<Self> {
        Self::new_inner(
            config,
            relay_generation,
            None,
            None,
            None,
            None,
            None,
            [1; 32],
        )
    }

    /// Binds one UDP QUIC endpoint with verified TLS 1.3 mutual authentication.
    ///
    /// # Parameters
    /// * `config` - Configuration containing certificate/key/CA paths.
    /// * `relay_generation` - Non-zero process startup epoch.
    ///
    /// # Returns
    /// A bound production server or a redacted bind/TLS error.
    pub async fn bind(config: RelayConfig, relay_generation: u64) -> RelayResult<Self> {
        if config.security().mode() != SecurityMode::Verified {
            return Err(RelayError::InvalidConfiguration {
                field: "security.mode",
                reason: "development_unverified is test-only",
            });
        }
        Self::bind_inner(config, relay_generation, None).await
    }

    /// Binds one UDP endpoint with a deterministic Unix socket override for tests.
    ///
    /// # Parameters
    /// * `config` - Validated QRM configuration.
    /// * `relay_generation` - Non-zero process startup epoch.
    /// * `socket_path` - Private test socket path used by every test session.
    ///
    /// # Returns
    /// A bound server whose bridge uses the supplied validated socket path.
    // TEST:relay/src/quic_server.rs[tests::server_accepts_only_valid_generation]
    #[cfg(any(test, feature = "contract-test-support"))]
    pub async fn bind_with_socket_path(
        config: RelayConfig,
        relay_generation: u64,
        socket_path: PathBuf,
    ) -> RelayResult<Self> {
        Self::bind_inner(config, relay_generation, Some(socket_path)).await
    }

    /// Binds a test-owned UDP socket without reopening the port between fixture setup and Relay startup.
    ///
    /// # Parameters
    /// * `config` - Validated QRM configuration whose listener address must match `socket`.
    /// * `relay_generation` - Non-zero process startup epoch.
    /// * `socket_path` - Private test socket path used by every test session.
    /// * `socket` - Already-bound nonblocking UDP socket owned by the test harness.
    ///
    /// # Returns
    /// A bound server using the supplied socket, or a redacted listener/TLS error.
    ///
    /// This seam is available only to contract tests so cross-crate disposable migrations can
    /// hold a selected port without a check-then-bind race; production callers use [`Self::bind`].
    // TEST:core/tests/qrm_e5_trust_bundle.rs[qrm_e5_disposable_bundle_rebind_and_rollback,qrm_e5_core_receives_on_wire_goaway]
    #[cfg(feature = "contract-test-support")]
    pub async fn bind_with_socket_path_on_socket(
        config: RelayConfig,
        relay_generation: u64,
        socket_path: PathBuf,
        socket: std::net::UdpSocket,
    ) -> RelayResult<Self> {
        socket
            .set_nonblocking(true)
            .map_err(|error| RelayError::io("configuring QRM UDP listener", error))?;
        Self::bind_inner_with_socket(config, relay_generation, Some(socket_path), Some(socket))
            .await
    }

    /// Returns the configured or actual UDP bind address.
    pub fn local_addr(&self) -> RelayResult<SocketAddr> {
        match &self.endpoint {
            Some(endpoint) => endpoint
                .local_addr()
                .map_err(|_| RelayError::ListenerStartup {
                    reason: "cannot read UDP listener address",
                }),
            None => self.config.listener().socket_addr(),
        }
    }

    /// Returns the Relay process startup generation.
    pub const fn relay_generation(&self) -> u64 {
        self.relay_generation
    }

    /// Returns the protected trust-bundle generation advertised by this server.
    pub const fn ca_generation(&self) -> u64 {
        self.ca_generation
    }

    /// Creates one contract registry for a fresh connection epoch.
    pub fn new_connection(&self, connection_epoch: u64) -> RelayResult<SessionRegistry> {
        SessionRegistry::new(
            self.relay_generation,
            connection_epoch,
            self.config.limits().max_sessions_per_connection(),
        )
    }

    /// Serves accepted QUIC connections until the caller's shutdown future resolves.
    ///
    /// # Parameters
    /// * `shutdown` - Future that completes when the process should stop.
    ///
    /// # Returns
    /// `Ok(())` after the endpoint and owned connection tasks are closed.
    // TEST:relay/src/quic_server.rs[tests::qrm_shutdown_sends_goaway_and_blocks_new_sessions]
    pub async fn serve_until<S>(self, shutdown: S) -> RelayResult<()>
    where
        S: std::future::Future<Output = ()> + Send + 'static,
    {
        let endpoint = self.endpoint.clone().ok_or(RelayError::ListenerStartup {
            reason: "QRM server is not bound to a UDP endpoint",
        })?;
        let server = Arc::new(self);
        let mut shutdown = Box::pin(shutdown);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    // Broadcast GOAWAY before closing the endpoint so existing connections can
                    // finish read-only work inside the bounded drain window.
                    let deadline = Instant::now() + QRM_DRAIN_TIMEOUT;
                    let _ = server.drain_tx.send(Some(deadline));
                    while !tasks.is_empty() {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        match timeout(remaining, tasks.join_next()).await {
                            Ok(Some(_)) => {}
                            Ok(None) | Err(_) => break,
                        }
                    }
                    endpoint.close(0u32.into(), b"shutdown");
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(());
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = joined;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { return Ok(()); };
                    let Some(handshake_permit) = try_acquire(&server.pre_auth_handshakes) else {
                        incoming.refuse();
                        continue;
                    };
                    let owner = Arc::clone(&server);
                    tasks.spawn(async move {
                        let mut drain_rx = owner.drain_tx.subscribe();
                        if drain_rx.borrow().is_some() {
                            return;
                        }
                        let connection = tokio::select! {
                            _ = drain_rx.changed() => return,
                            result = timeout(owner.handshake_timeout(), incoming) => match result {
                                Ok(Ok(connection)) => connection,
                                _ => return,
                            },
                        };
                        drop(handshake_permit);
                        let is_pre_auth = negotiated_alpn(&connection)
                            .map(|protocol| {
                                protocol == QRM_ENROLLMENT_ALPN || protocol == QRM_BOOTSTRAP_ALPN
                            })
                            .unwrap_or(false);
                        let connection_permit = if is_pre_auth {
                            None
                        } else {
                            let Some(permit) = try_acquire(&owner.connections) else {
                                connection.close(0u32.into(), b"connection quota");
                                return;
                            };
                            Some(permit)
                        };
                        if let Err(error) = owner
                            .serve_connection(connection, connection_permit)
                            .await
                        {
                            eprintln!("herdogrelay: connection closed: {error}");
                        }
                    });
                }
            }
        }
    }

    /// Binds a one-listener Quinn endpoint with the configured TLS policy.
    async fn bind_inner(
        config: RelayConfig,
        relay_generation: u64,
        socket_override: Option<PathBuf>,
    ) -> RelayResult<Self> {
        Self::bind_inner_with_socket(config, relay_generation, socket_override, None).await
    }

    /// Builds a Relay endpoint from either a newly bound or a test-prebound UDP socket.
    async fn bind_inner_with_socket(
        config: RelayConfig,
        relay_generation: u64,
        socket_override: Option<PathBuf>,
        prebound_socket: Option<std::net::UdpSocket>,
    ) -> RelayResult<Self> {
        let address = config.listener().socket_addr()?;
        let server_config = build_server_config(&config)?;
        let endpoint = match prebound_socket {
            Some(socket) => {
                let actual_address = socket
                    .local_addr()
                    .map_err(|error| RelayError::io("reading QRM UDP listener address", error))?;
                if actual_address != address {
                    return Err(RelayError::ListenerStartup {
                        reason: "prebound QRM UDP listener address does not match configuration",
                    });
                }
                let runtime = quinn::default_runtime().ok_or(RelayError::ListenerStartup {
                    reason: "Tokio QUIC runtime is unavailable",
                })?;
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    socket,
                    runtime,
                )
                .map_err(|error| RelayError::io("binding QRM UDP listener", error))?
            }
            None => quinn::Endpoint::server(server_config, address)
                .map_err(|error| RelayError::io("binding QRM UDP listener", error))?,
        };
        let relay_identity = load_relay_identity(&config)?;
        // Enrollment may be disabled, but verified normal QRM still requires an active allowlist.
        let (allowlist, issuance_results, bootstrap) = if config.security().mode()
            == SecurityMode::Verified
        {
            let uid = current_uid()?;
            let allowlist = Arc::new(Mutex::new(PersistentAllowlist::open(
                config.enrollment().allowlist_path(),
                uid,
            )?));
            let issuance_results = config
                .enrollment()
                .enabled()
                .then(|| {
                    PersistentIssuanceResults::open(config.enrollment().issuance_result_path(), uid)
                        .map(|store| Arc::new(Mutex::new(store)))
                })
                .transpose()?;
            let bootstrap = config
                .enrollment()
                .enabled()
                .then(|| BootstrapRuntime::new(&config, uid).map(Arc::new))
                .transpose()?;
            (Some(allowlist), issuance_results, bootstrap)
        } else {
            (None, None, None)
        };
        Self::new_inner(
            config,
            relay_generation,
            Some(endpoint),
            socket_override,
            allowlist,
            issuance_results,
            bootstrap,
            relay_identity,
        )
    }

    /// Constructs the owner after common validation and optional production bootstrap wiring.
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        config: RelayConfig,
        relay_generation: u64,
        endpoint: Option<quinn::Endpoint>,
        socket_override: Option<PathBuf>,
        allowlist: Option<Arc<Mutex<PersistentAllowlist>>>,
        issuance_results: Option<Arc<Mutex<PersistentIssuanceResults>>>,
        bootstrap: Option<Arc<BootstrapRuntime>>,
        relay_identity: [u8; 32],
    ) -> RelayResult<Self> {
        if relay_generation == 0 {
            return Err(RelayError::ListenerStartup {
                reason: "Relay generation must be non-zero",
            });
        }
        config.validate()?;
        let ca_generation = config.security().ca_generation();
        let (drain_tx, _) = watch::channel(None);
        Ok(Self {
            connections: Arc::new(Semaphore::new(config.limits().max_connections())),
            pre_auth_handshakes: Arc::new(Semaphore::new(
                config
                    .limits()
                    .max_connections()
                    .saturating_add(config.enrollment().max_handshakes()),
            )),
            bootstrap_handshakes: Arc::new(Semaphore::new(config.enrollment().max_handshakes())),
            bootstrap_connections: Arc::new(Semaphore::new(config.enrollment().max_connections())),
            enrollment_handshakes: Arc::new(Semaphore::new(config.enrollment().max_handshakes())),
            enrollment_connections: Arc::new(Semaphore::new(config.enrollment().max_connections())),
            config,
            relay_generation,
            relay_identity,
            ca_generation,
            endpoint,
            issuance_results,
            allowlist,
            drain_tx,
            bootstrap,
            socket_override,
        })
    }

    /// Wraps one connection so every terminal control error explicitly closes QUIC.
    async fn serve_connection(
        &self,
        connection: quinn::Connection,
        _connection_permit: Option<OwnedSemaphorePermit>,
    ) -> RelayResult<()> {
        let result = self.serve_connection_inner(connection.clone()).await;
        if result.is_err() {
            connection.close(0u32.into(), b"protocol failure");
        }
        result
    }

    /// Handles one authenticated connection and owns its control/session tasks.
    async fn serve_connection_inner(&self, connection: quinn::Connection) -> RelayResult<()> {
        let protocol = negotiated_alpn(&connection)?;
        if protocol == QRM_BOOTSTRAP_ALPN {
            if !self.config.enrollment().enabled() {
                return Err(RelayError::QuicProtocol {
                    reason: "bootstrap ALPN is disabled",
                });
            }
            return self.serve_bootstrap_connection(connection).await;
        }
        let peer_fingerprint = if self.config.security().mode() == SecurityMode::Verified {
            Some(peer_certificate_fingerprint(&connection)?)
        } else {
            None
        };
        if protocol == QRM_ENROLLMENT_ALPN {
            if !self.config.enrollment().enabled() {
                return Err(RelayError::QuicProtocol {
                    reason: "enrollment ALPN is disabled",
                });
            }
            if !peer_certificate_matches_anchor(
                &connection,
                self.config.security().trusted_core_enrollment_ca(),
            )? {
                return Err(RelayError::QuicAuthentication);
            }
            let connection_for_close = connection.clone();
            let result = self
                .serve_hde3_connection(
                    connection,
                    peer_fingerprint.ok_or(RelayError::QuicAuthentication)?,
                )
                .await;
            if result.is_ok() {
                connection_for_close.close(0u32.into(), b"enrollment terminal");
            }
            return result;
        }
        if protocol != QRM_RELAY_ALPN {
            return Err(RelayError::QuicProtocol {
                reason: "unsupported QRM ALPN",
            });
        }
        if self.config.security().mode() == SecurityMode::Verified {
            // A valid TLS chain alone never admits normal QRM; the active allowlist is mandatory.
            let allowlist = self
                .allowlist
                .as_ref()
                .ok_or(RelayError::QuicAuthentication)?;
            let fingerprint = peer_fingerprint.ok_or(RelayError::QuicAuthentication)?;
            if !allowlist.lock().await.allows_qrm(fingerprint) {
                return Err(RelayError::QuicAuthentication);
            }
        }
        let connection_epoch = rand::random::<u64>().max(1);
        let registry = Arc::new(Mutex::new(self.new_connection(connection_epoch)?));
        let session_controls: SessionTaskControls = Arc::new(Mutex::new(BTreeMap::new()));
        let mut session_tasks = JoinSet::new();
        let mut expiry_tick = tokio::time::interval(Duration::from_secs(1));
        let (mut control_send, mut control_recv) =
            timeout(self.handshake_timeout(), connection.accept_bi())
                .await
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "control stream timeout",
                })?
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "control stream unavailable",
                })?;
        let hello = read_control_frame_timed(&mut control_recv, self.handshake_timeout()).await?;
        if hello.kind != HdqmKind::DeviceHello {
            return Err(RelayError::QuicProtocol {
                reason: "first control frame is not DEVICE_HELLO",
            });
        }
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::DeviceHelloAck,
                request_id: hello.request_id,
                payload: DeviceHelloAck {
                    relay_identity: self.relay_identity,
                    ca_generation: self.ca_generation,
                    relay_generation: self.relay_generation,
                    connection_epoch,
                }
                .encode(),
            },
        )
        .await?;
        let mut control_frames = spawn_control_reader(
            control_recv,
            Duration::from_secs(self.config.limits().idle_timeout_secs()),
        );
        let mut drain_rx = self.drain_tx.subscribe();
        let mut draining = drain_rx.borrow().is_some();
        let mut drain_deadline = *drain_rx.borrow();
        if draining {
            self.send_go_away(&mut control_send).await?;
        }
        loop {
            let drain_wait = Self::wait_for_drain_deadline(drain_deadline);
            tokio::pin!(drain_wait);
            tokio::select! {
                changed = drain_rx.changed(), if !draining => {
                    if let Ok(()) = changed {
                        let deadline: Option<Instant> = *drain_rx.borrow();
                        if let Some(deadline) = deadline {
                            self.send_go_away(&mut control_send).await?;
                            draining = true;
                            drain_deadline = Some(deadline);
                        }
                    }
                }
                _ = &mut drain_wait, if draining => {
                    session_tasks.abort_all();
                    while session_tasks.join_next().await.is_some() {}
                    connection.close(0u32.into(), b"drain deadline");
                    return Ok(());
                }
                _ = expiry_tick.tick() => {
                    // Recheck the persistent allowlist independently of control traffic so a
                    // local revoke closes an idle connection and all of its matching sessions.
                    if let (Some(allowlist), Some(fingerprint)) = (&self.allowlist, peer_fingerprint) {
                        let allowed = {
                            let mut allowlist = allowlist.lock().await;
                            allowlist.reload().is_ok() && allowlist.allows_qrm(fingerprint)
                        };
                        if !allowed {
                            session_tasks.abort_all();
                            while session_tasks.join_next().await.is_some() {}
                            connection.close(0u32.into(), b"allowlist revoked");
                            return Ok(());
                        }
                    }
                    let expired = registry.lock().await.reap_expired_handles(Instant::now());
                    for handle in expired {
                        self.cancel_session(&session_controls, handle).await;
                    }
                }
                joined = session_tasks.join_next(), if !session_tasks.is_empty() => {
                    let _ = joined;
                    if draining && session_tasks.is_empty() {
                        // Once the last existing session has finished, the bounded drain can
                        // complete without waiting for the full deadline.
                        connection.close(0u32.into(), b"drain complete");
                        return Ok(());
                    }
                }
                control = control_frames.recv() => {
                    let Some(control) = control else {
                        session_tasks.abort_all();
                        while session_tasks.join_next().await.is_some() {}
                        return Ok(());
                    };
                    let frame = match control {
                        Ok(frame) => frame,
                        Err(error) => {
                            session_tasks.abort_all();
                            while session_tasks.join_next().await.is_some() {}
                            return Err(error);
                        }
                    };
                    let keep_open = match self
                        .handle_control(
                            frame,
                            &mut control_send,
                            &registry,
                            &session_controls,
                            peer_fingerprint,
                            !draining,
                        )
                        .await {
                        Ok(keep_open) => keep_open,
                        Err(error) => {
                            session_tasks.abort_all();
                            while session_tasks.join_next().await.is_some() {}
                            return Err(error);
                        }
                    };
                    if !keep_open {
                        session_tasks.abort_all();
                        while session_tasks.join_next().await.is_some() {}
                        connection.close(0u32.into(), b"control close");
                        return Ok(());
                    }
                }
                session = connection.accept_bi(), if !draining => {
                    let (send, recv) = match session {
                        Ok(stream) => stream,
                        Err(_) => {
                            session_tasks.abort_all();
                            while session_tasks.join_next().await.is_some() {}
                            return Err(RelayError::QuicProtocol { reason: "session stream accept failed" });
                        }
                    };
                    let owner = self.clone_for_task();
                    let registry_for_task = Arc::clone(&registry);
                    let controls = Arc::clone(&session_controls);
                    let connection_for_task = connection.clone();
                    session_tasks.spawn(async move {
                        if let Err(error) = owner
                            .serve_session_stream(
                                connection_for_task,
                                send,
                                recv,
                                registry_for_task,
                                controls,
                            )
                            .await
                        {
                            eprintln!("herdogrelay: session stream closed: {error}");
                        }
                    });
                }
            }
        }
    }

    /// Cancel one exact session bridge and wait for its resources to be dropped.
    async fn cancel_session(&self, controls: &SessionTaskControls, handle: u16) {
        let control = controls.lock().await.remove(&handle);
        let Some(control) = control else {
            return;
        };
        let done_wait = control.done.notified();
        let _ = control.cancel.send(());
        let _ = timeout(self.handshake_timeout(), done_wait).await;
    }

    /// Handles one typed HDQM control operation.
    async fn handle_control(
        &self,
        frame: HdqmFrame,
        send: &mut quinn::SendStream,
        registry: &Arc<Mutex<SessionRegistry>>,
        session_controls: &SessionTaskControls,
        peer_fingerprint: Option<Fingerprint>,
        accept_new_sessions: bool,
    ) -> RelayResult<bool> {
        if !accept_new_sessions
            && matches!(frame.kind, HdqmKind::SessionPrepare | HdqmKind::SessionOpen)
        {
            // GOAWAY is a connection-level admission fence. Existing session close and
            // heartbeat frames remain processable during the bounded read-only drain.
            let epoch = registry.lock().await.connection_epoch();
            let response = HdqsResponse::rejected(HdqsReason::ConnectionClosing, epoch);
            send_control_frame(
                send,
                HdqmFrame {
                    kind: HdqmKind::ErrorResponse,
                    request_id: frame.request_id,
                    payload: response
                        .encode()
                        .map_err(|_| RelayError::QuicProtocol {
                            reason: "drain rejection encoding failed",
                        })?
                        .to_vec(),
                },
            )
            .await?;
            return Ok(true);
        }
        if let (Some(allowlist), Some(fingerprint)) = (&self.allowlist, peer_fingerprint) {
            let mut allowlist = allowlist.lock().await;
            allowlist.reload()?;
            if !allowlist.allows_qrm(fingerprint) {
                return Err(RelayError::QuicAuthentication);
            }
        }
        match frame.kind {
            HdqmKind::SessionPrepare => {
                let request = SessionPrepareRequest::decode(&frame.payload).map_err(|_| {
                    RelayError::QuicProtocol {
                        reason: "SESSION_PREPARE payload invalid",
                    }
                })?;
                let fingerprint = if request.expected_fingerprint == [0; 32] {
                    rand::random::<[u8; 32]>()
                } else {
                    request.expected_fingerprint
                };
                let token = rand::random::<[u8; 32]>();
                let (prepared_result, connection_epoch) = {
                    let mut registry = registry.lock().await;
                    registry.reap_expired_prepared(Instant::now());
                    let result = registry.prepare(
                        request.session.as_str(),
                        fingerprint,
                        request.configuration_generation,
                        token,
                    );
                    (result, registry.connection_epoch())
                };
                let prepared = match prepared_result {
                    Ok(prepared) => prepared,
                    Err(RelayError::ResourceLimit) => {
                        let error =
                            HdqsResponse::rejected(HdqsReason::CapacityExhausted, connection_epoch);
                        send_control_frame(
                            send,
                            HdqmFrame {
                                kind: HdqmKind::ErrorResponse,
                                request_id: frame.request_id,
                                payload: error
                                    .encode()
                                    .map_err(|_| RelayError::QuicProtocol {
                                        reason: "SESSION_PREPARE capacity error encoding failed",
                                    })?
                                    .to_vec(),
                            },
                        )
                        .await?;
                        return Ok(true);
                    }
                    Err(RelayError::SessionAuthority) => {
                        let error =
                            HdqsResponse::rejected(HdqsReason::SessionNotFound, connection_epoch);
                        send_control_frame(
                            send,
                            HdqmFrame {
                                kind: HdqmKind::ErrorResponse,
                                request_id: frame.request_id,
                                payload: error
                                    .encode()
                                    .map_err(|_| RelayError::QuicProtocol {
                                        reason: "SESSION_PREPARE authority error encoding failed",
                                    })?
                                    .to_vec(),
                            },
                        )
                        .await?;
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                };
                let response = SessionPrepareAck {
                    session: prepared.session,
                    fingerprint: prepared.fingerprint,
                    configuration_generation: prepared.configuration_generation,
                    relay_generation: prepared.relay_generation,
                    connection_epoch: prepared.connection_epoch,
                    token: prepared.token,
                    token_ttl_secs: prepared.token_ttl_secs,
                };
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::SessionPrepareAck,
                        request_id: frame.request_id,
                        payload: response.encode().map_err(|_| RelayError::QuicProtocol {
                            reason: "SESSION_PREPARE_ACK encoding failed",
                        })?,
                    },
                )
                .await?;
            }
            HdqmKind::SessionOpen => {
                let request = SessionOpenRequest::decode(&frame.payload).map_err(|_| {
                    RelayError::QuicProtocol {
                        reason: "SESSION_OPEN payload invalid",
                    }
                })?;
                let (response, active) = registry.lock().await.open_request(&request);
                let Some(active) = active else {
                    send_control_frame(
                        send,
                        HdqmFrame {
                            kind: HdqmKind::ErrorResponse,
                            request_id: frame.request_id,
                            payload: response
                                .encode()
                                .map_err(|_| RelayError::QuicProtocol {
                                    reason: "SESSION_OPEN error encoding failed",
                                })?
                                .to_vec(),
                        },
                    )
                    .await?;
                    return Ok(true);
                };
                let ack = SessionOpenAck {
                    session_handle: active.handle,
                    session: active.prepared.session,
                    fingerprint: active.prepared.fingerprint,
                    configuration_generation: active.prepared.configuration_generation,
                    relay_generation: active.prepared.relay_generation,
                    connection_epoch: active.prepared.connection_epoch,
                    token: active.prepared.token,
                };
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::SessionOpened,
                        request_id: frame.request_id,
                        payload: ack.encode().map_err(|_| RelayError::QuicProtocol {
                            reason: "SESSION_OPEN_ACK encoding failed",
                        })?,
                    },
                )
                .await?;
            }
            HdqmKind::SessionClose => {
                if frame.payload.len() != 2 {
                    return Err(RelayError::QuicProtocol {
                        reason: "SESSION_CLOSE payload invalid",
                    });
                }
                let handle = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                registry.lock().await.close(handle);
                self.cancel_session(session_controls, handle).await;
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::SessionClosed,
                        request_id: frame.request_id,
                        payload: Vec::new(),
                    },
                )
                .await?;
            }
            HdqmKind::Heartbeat => {
                if frame.payload.is_empty() {
                    return Err(RelayError::QuicProtocol {
                        reason: "HEARTBEAT payload is empty",
                    });
                }
                let count = usize::from(frame.payload[0]);
                if count > 64 || frame.payload.len() != 1 + count * 34 {
                    return Err(RelayError::QuicProtocol {
                        reason: "HEARTBEAT payload is invalid",
                    });
                }
                let mut entries = Vec::with_capacity(count);
                for index in 0..count {
                    let offset = 1 + index * 34;
                    let handle =
                        u16::from_be_bytes([frame.payload[offset], frame.payload[offset + 1]]);
                    let mut token = [0_u8; 32];
                    token.copy_from_slice(&frame.payload[offset + 2..offset + 34]);
                    entries.push((handle, token));
                }
                let (renewed, connection_epoch) = {
                    let mut registry = registry.lock().await;
                    let renewed = registry.renew_batch(&entries, Instant::now());
                    (renewed, registry.connection_epoch())
                };
                if !renewed {
                    let error = HdqsResponse::rejected(HdqsReason::TokenMismatch, connection_epoch);
                    send_control_frame(
                        send,
                        HdqmFrame {
                            kind: HdqmKind::ErrorResponse,
                            request_id: frame.request_id,
                            payload: error
                                .encode()
                                .map_err(|_| RelayError::QuicProtocol {
                                    reason: "HEARTBEAT error encoding failed",
                                })?
                                .to_vec(),
                        },
                    )
                    .await?;
                    return Ok(true);
                }
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::Heartbeat,
                        request_id: frame.request_id,
                        payload: Vec::new(),
                    },
                )
                .await?;
            }
            HdqmKind::RelayUpdate => {
                if !self.config.update().enabled() {
                    return Err(RelayError::QuicProtocol {
                        reason: "Relay update is disabled",
                    });
                }
                if frame.payload.as_slice() != STABLE_LATEST_SELECTOR.as_bytes() {
                    send_control_frame(
                        send,
                        HdqmFrame {
                            kind: HdqmKind::RelayUpdateRejected,
                            request_id: frame.request_id,
                            payload: vec![1],
                        },
                    )
                    .await?;
                    return Ok(true);
                }
                let authorized = if let (Some(allowlist), Some(fingerprint)) =
                    (&self.allowlist, peer_fingerprint)
                {
                    let mut allowlist = allowlist.lock().await;
                    allowlist.reload()?;
                    allowlist.authorize_update(fingerprint).is_ok()
                } else {
                    false
                };
                if !authorized {
                    send_control_frame(
                        send,
                        HdqmFrame {
                            kind: HdqmKind::RelayUpdateRejected,
                            request_id: frame.request_id,
                            payload: vec![2],
                        },
                    )
                    .await?;
                    return Ok(true);
                }
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::RelayUpdateAccepted,
                        request_id: frame.request_id,
                        payload: vec![1],
                    },
                )
                .await?;
                let update_config = self.config.clone();
                let result = tokio::task::spawn_blocking(move || {
                    perform_stable_latest_update(update_config)
                })
                .await
                .map_err(|_| RelayError::Update {
                    operation: "running stable-latest update",
                    reason: "update worker task failed",
                })?;
                if result.is_err() {
                    send_control_frame(
                        send,
                        HdqmFrame {
                            kind: HdqmKind::RelayUpdateStatus,
                            request_id: frame.request_id,
                            payload: vec![2],
                        },
                    )
                    .await?;
                    return Ok(true);
                }
                send_control_frame(
                    send,
                    HdqmFrame {
                        kind: HdqmKind::RelayUpdateStatus,
                        request_id: frame.request_id,
                        payload: vec![1],
                    },
                )
                .await?;
                return Ok(false);
            }
            HdqmKind::GoAway => return Ok(false),
            HdqmKind::DeviceHello
            | HdqmKind::DeviceHelloAck
            | HdqmKind::SessionPrepareAck
            | HdqmKind::SessionOpened
            | HdqmKind::SessionClosed
            | HdqmKind::ErrorResponse
            | HdqmKind::RelayUpdateAccepted
            | HdqmKind::RelayUpdateRejected
            | HdqmKind::RelayUpdateStatus => {
                return Err(RelayError::QuicProtocol {
                    reason: "unexpected control frame kind",
                });
            }
        }
        Ok(true)
    }

    /// Builds one HDB1 response for a fresh or resumed code submission.
    async fn bootstrap_submit_response(
        &self,
        bootstrap: &BootstrapRuntime,
        frame: crate::bootstrap_wire::Hdb1Frame,
    ) -> RelayResult<crate::bootstrap_wire::Hdb1Frame> {
        let submit: crate::bootstrap_wire::Hdb1SubmitPayload =
            match frame.parse_json(crate::bootstrap_wire::Hdb1Kind::Submit) {
                Ok(payload) => payload,
                Err(_) => return hdb1_rejection_frame(1),
            };
        let (bootstrap_id, submitted_challenge, code) = match submit.decode_fields() {
            Ok(fields) => fields,
            Err(_) => return hdb1_rejection_frame(1),
        };
        match bootstrap
            .submit(bootstrap_id, submitted_challenge, &code)
            .await
        {
            Ok(issued) => {
                let payload = crate::bootstrap_wire::Hdb1CoreIssuedPayload::new(
                    issued.approval_id,
                    issued.core_identity,
                    &issued.certificate_chain,
                    issued.not_after_epoch_seconds,
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "bootstrap issuance response is invalid",
                })?;
                crate::bootstrap_wire::Hdb1Frame::json(
                    crate::bootstrap_wire::Hdb1Kind::CoreIssued,
                    &payload,
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "bootstrap issuance response is invalid",
                })
            }
            Err(error) => {
                let payload = crate::bootstrap_wire::Hdb1RejectedPayload::new(
                    bootstrap_rejection_code(error),
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "bootstrap rejection encoding failed",
                })?;
                crate::bootstrap_wire::Hdb1Frame::json(
                    crate::bootstrap_wire::Hdb1Kind::Rejected,
                    &payload,
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "bootstrap rejection encoding failed",
                })
            }
        }
    }

    /// Handles one server-only HDB1 bootstrap connection before any Core certificate exists.
    async fn serve_bootstrap_connection(&self, connection: quinn::Connection) -> RelayResult<()> {
        let bootstrap = self.bootstrap.as_ref().ok_or(RelayError::QuicProtocol {
            reason: "bootstrap runtime is unavailable",
        })?;
        let _handshake_permit =
            try_acquire(&self.bootstrap_handshakes).ok_or(RelayError::ResourceLimit)?;
        let _connection_permit =
            try_acquire(&self.bootstrap_connections).ok_or(RelayError::ResourceLimit)?;
        let connection_deadline =
            Instant::now() + Duration::from_secs(BOOTSTRAP_HARD_LIFETIME_SECS);
        let (mut send, mut recv) = timeout(
            bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
            connection.accept_bi(),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "bootstrap stream timeout",
        })?
        .map_err(|_| RelayError::QuicHandshake {
            reason: "bootstrap stream unavailable",
        })?;
        let start = match timeout(
            remaining_bootstrap_time(connection_deadline),
            crate::bootstrap_wire::read_frame(&mut recv),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => {
                let _ = send_hdb1_rejection(&mut send, 1).await;
                connection.close(0u32.into(), b"bootstrap frame invalid");
                return Ok(());
            }
        };
        if start.kind() == crate::bootstrap_wire::Hdb1Kind::Submit {
            let response = self.bootstrap_submit_response(bootstrap, start).await?;
            timeout(
                bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
                crate::bootstrap_wire::write_frame(&mut send, &response),
            )
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "bootstrap resumed response timeout",
            })?
            .map_err(|_| RelayError::QuicProtocol {
                reason: "bootstrap resumed response failed",
            })?;
            send.finish().map_err(|_| RelayError::QuicProtocol {
                reason: "finishing resumed bootstrap stream",
            })?;
            let _ = timeout(
                bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
                send.stopped(),
            )
            .await;
            return Ok(());
        }
        if start.kind() == crate::bootstrap_wire::Hdb1Kind::Reconcile {
            let payload: crate::bootstrap_wire::Hdb1ReconcilePayload =
                match start.parse_json(crate::bootstrap_wire::Hdb1Kind::Reconcile) {
                    Ok(payload) => payload,
                    Err(_) => {
                        let _ = send_hdb1_rejection(&mut send, 1).await;
                        connection.close(0u32.into(), b"bootstrap reconcile invalid");
                        return Ok(());
                    }
                };
            let (approval_id, binding_digest, session) = match payload.decode_fields() {
                Ok(fields) => fields,
                Err(_) => {
                    let _ = send_hdb1_rejection(&mut send, 1).await;
                    connection.close(0u32.into(), b"bootstrap reconcile invalid");
                    return Ok(());
                }
            };
            let response = match bootstrap
                .reconcile(approval_id, binding_digest, &session)
                .await
            {
                Ok(issued) => {
                    let payload = crate::bootstrap_wire::Hdb1ResultPayload::new_issued(
                        issued.approval_id,
                        issued.core_identity,
                        &issued.certificate_chain,
                        issued.not_after_epoch_seconds,
                    )
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "bootstrap reconcile result is invalid",
                    })?;
                    crate::bootstrap_wire::Hdb1Frame::json(
                        crate::bootstrap_wire::Hdb1Kind::Result,
                        &payload,
                    )
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "bootstrap reconcile result is invalid",
                    })?
                }
                Err(error) => {
                    let payload = crate::bootstrap_wire::Hdb1RejectedPayload::new(
                        bootstrap_rejection_code(error),
                    )
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "bootstrap reconcile rejection is invalid",
                    })?;
                    crate::bootstrap_wire::Hdb1Frame::json(
                        crate::bootstrap_wire::Hdb1Kind::Rejected,
                        &payload,
                    )
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "bootstrap reconcile rejection is invalid",
                    })?
                }
            };
            timeout(
                bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
                crate::bootstrap_wire::write_frame(&mut send, &response),
            )
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "bootstrap reconcile response timeout",
            })?
            .map_err(|_| RelayError::QuicProtocol {
                reason: "bootstrap reconcile response failed",
            })?;
            send.finish().map_err(|_| RelayError::QuicProtocol {
                reason: "finishing bootstrap reconcile stream",
            })?;
            connection.close(0u32.into(), b"bootstrap reconcile terminal");
            return Ok(());
        }
        let payload = match start.parse_json(crate::bootstrap_wire::Hdb1Kind::Start) {
            Ok(payload) => payload,
            Err(_) => {
                let _ = send_hdb1_rejection(&mut send, 1).await;
                connection.close(0u32.into(), b"bootstrap order invalid");
                return Ok(());
            }
        };
        let challenge = match bootstrap
            .start(connection.remote_address().ip(), payload)
            .await
        {
            Ok(challenge) => challenge,
            Err(error) => {
                let _ = send_hdb1_rejection(&mut send, bootstrap_rejection_code(error)).await;
                connection.close(0u32.into(), b"bootstrap rejected");
                return Ok(());
            }
        };
        let challenge_payload = crate::bootstrap_wire::Hdb1ChallengePayload::new(
            challenge.bootstrap_id,
            challenge.challenge,
            challenge.expires_at_epoch_seconds,
        )
        .map_err(|_| RelayError::QuicProtocol {
            reason: "bootstrap challenge encoding failed",
        })?;
        let challenge_frame = crate::bootstrap_wire::Hdb1Frame::json(
            crate::bootstrap_wire::Hdb1Kind::Challenge,
            &challenge_payload,
        )
        .map_err(|_| RelayError::QuicProtocol {
            reason: "bootstrap challenge encoding failed",
        })?;
        timeout(
            bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
            crate::bootstrap_wire::write_frame(&mut send, &challenge_frame),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "bootstrap challenge write timeout",
        })?
        .map_err(|_| RelayError::QuicProtocol {
            reason: "bootstrap challenge write failed",
        })?;
        let submit = match timeout(
            remaining_bootstrap_time(connection_deadline),
            crate::bootstrap_wire::read_frame(&mut recv),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => {
                connection.close(0u32.into(), b"bootstrap submit missing");
                return Ok(());
            }
        };
        let response = self.bootstrap_submit_response(bootstrap, submit).await?;
        timeout(
            bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
            crate::bootstrap_wire::write_frame(&mut send, &response),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "bootstrap response write timeout",
        })?
        .map_err(|_| RelayError::QuicProtocol {
            reason: "bootstrap response write failed",
        })?;
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing bootstrap stream",
        })?;
        let _ = timeout(
            bounded_bootstrap_timeout(connection_deadline, self.handshake_timeout()),
            send.stopped(),
        )
        .await;
        connection.close(0u32.into(), b"bootstrap terminal");
        Ok(())
    }

    /// Handles one Core-enrollment mTLS connection using only the frozen HDE3 registry.
    async fn serve_hde3_connection(
        &self,
        connection: quinn::Connection,
        core_fingerprint: Fingerprint,
    ) -> RelayResult<()> {
        let bootstrap = self.bootstrap.as_ref().ok_or(RelayError::QuicProtocol {
            reason: "enrollment authority is unavailable",
        })?;
        let _handshake_permit =
            try_acquire(&self.enrollment_handshakes).ok_or(RelayError::ResourceLimit)?;
        let _connection_permit =
            try_acquire(&self.enrollment_connections).ok_or(RelayError::ResourceLimit)?;
        let (mut send, mut recv) = timeout(self.handshake_timeout(), connection.accept_bi())
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "HDE3 stream timeout",
            })?
            .map_err(|_| RelayError::QuicHandshake {
                reason: "HDE3 stream unavailable",
            })?;
        let frame = match timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            crate::enrollment_v3_wire::read_frame(&mut recv),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) | Err(_) => {
                let _ = send_hde3_rejection(&mut send, None, 1).await;
                return Ok(());
            }
        };
        match frame.kind() {
            crate::enrollment_v3_wire::Hde3Kind::ApprovalSubmit => {
                let payload: crate::enrollment_v3_wire::Hde3ApprovalSubmitPayload =
                    match frame.parse_json(crate::enrollment_v3_wire::Hde3Kind::ApprovalSubmit) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                let (approval_id, submitted_challenge, code, app_csr, digest) =
                    match payload.decode_fields() {
                        Ok(fields) => fields,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                let context = match bootstrap
                    .submit_app_approval(approval_id, submitted_challenge, &code, app_csr, digest)
                    .await
                {
                    Ok(context) => context,
                    Err(error) => {
                        send_hde3_rejection(
                            &mut send,
                            Some(approval_id),
                            bootstrap_rejection_code(error),
                        )
                        .await?;
                        return Ok(());
                    }
                };
                let result = self
                    .issue_hde3_app(
                        context.approval_id,
                        context.app_csr,
                        context.app_csr_digest,
                        context.configuration_generation,
                    )
                    .await;
                self.send_hde3_result(&mut send, result).await?;
            }
            crate::enrollment_v3_wire::Hde3Kind::FirstAppSubmit => {
                let payload: crate::enrollment_v3_wire::Hde3FirstAppSubmitPayload =
                    match frame.parse_json(crate::enrollment_v3_wire::Hde3Kind::FirstAppSubmit) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                let (approval_id, app_csr, app_csr_digest) = match payload.decode_fields() {
                    Ok(fields) => fields,
                    Err(_) => {
                        send_hde3_rejection(&mut send, None, 1).await?;
                        return Ok(());
                    }
                };
                let configuration_generation = match bootstrap
                    .authorize_first_app(core_fingerprint.to_bytes(), approval_id, app_csr_digest)
                    .await
                {
                    Ok(generation) => generation,
                    Err(_) => {
                        send_hde3_rejection(&mut send, Some(approval_id), 4).await?;
                        return Ok(());
                    }
                };
                let result = self
                    .issue_hde3_app(
                        approval_id,
                        app_csr,
                        app_csr_digest,
                        configuration_generation,
                    )
                    .await;
                self.send_hde3_result(&mut send, result).await?;
            }
            crate::enrollment_v3_wire::Hde3Kind::ApprovalStart => {
                let payload: crate::enrollment_v3_wire::Hde3ApprovalStartPayload =
                    match frame.parse_json(crate::enrollment_v3_wire::Hde3Kind::ApprovalStart) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                if payload.validate().is_err() {
                    send_hde3_rejection(&mut send, None, 1).await?;
                    return Ok(());
                }
                let app_csr_digest =
                    payload
                        .app_csr_digest()
                        .map_err(|_| RelayError::QuicProtocol {
                            reason: "HDE3 approval digest is invalid",
                        })?;
                let core_binding_digest = decode_hex_digest(&payload.core_binding_digest)?;
                let challenge = match bootstrap
                    .start_app_approval(
                        core_fingerprint.to_bytes(),
                        app_csr_digest,
                        core_binding_digest,
                        payload.normalized_session.clone(),
                        payload.configuration_generation,
                    )
                    .await
                {
                    Ok(challenge) => challenge,
                    Err(error) => {
                        send_hde3_rejection(&mut send, None, bootstrap_rejection_code(error))
                            .await?;
                        return Ok(());
                    }
                };
                let challenge_payload =
                    crate::enrollment_v3_wire::Hde3ApprovalChallengePayload::new(
                        challenge.approval_id,
                        challenge.challenge,
                        challenge.expires_at_epoch_seconds,
                    )
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "HDE3 challenge encoding failed",
                    })?;
                let challenge_frame = crate::enrollment_v3_wire::Hde3Frame::json(
                    crate::enrollment_v3_wire::Hde3Kind::ApprovalChallenge,
                    &challenge_payload,
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "HDE3 challenge encoding failed",
                })?;
                timeout(
                    self.handshake_timeout(),
                    crate::enrollment_v3_wire::write_frame(&mut send, &challenge_frame),
                )
                .await
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "HDE3 challenge write timeout",
                })?
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "HDE3 challenge write failed",
                })?;
                let submit = match timeout(
                    Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
                    crate::enrollment_v3_wire::read_frame(&mut recv),
                )
                .await
                {
                    Ok(Ok(frame)) => frame,
                    Ok(Err(_)) | Err(_) => return Ok(()),
                };
                let submit: crate::enrollment_v3_wire::Hde3ApprovalSubmitPayload =
                    match submit.parse_json(crate::enrollment_v3_wire::Hde3Kind::ApprovalSubmit) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, Some(challenge.approval_id), 1).await?;
                            return Ok(());
                        }
                    };
                let (approval_id, submitted_challenge, code, app_csr, digest) =
                    match submit.decode_fields() {
                        Ok(fields) => fields,
                        Err(_) => {
                            send_hde3_rejection(&mut send, Some(challenge.approval_id), 1).await?;
                            return Ok(());
                        }
                    };
                if approval_id != challenge.approval_id
                    || submitted_challenge != challenge.challenge
                {
                    send_hde3_rejection(&mut send, Some(challenge.approval_id), 4).await?;
                    return Ok(());
                }
                let context = match bootstrap
                    .submit_app_approval(approval_id, submitted_challenge, &code, app_csr, digest)
                    .await
                {
                    Ok(context) => context,
                    Err(error) => {
                        send_hde3_rejection(
                            &mut send,
                            Some(approval_id),
                            bootstrap_rejection_code(error),
                        )
                        .await?;
                        return Ok(());
                    }
                };
                let result = self
                    .issue_hde3_app(
                        context.approval_id,
                        context.app_csr,
                        context.app_csr_digest,
                        context.configuration_generation,
                    )
                    .await;
                self.send_hde3_result(&mut send, result).await?;
            }
            crate::enrollment_v3_wire::Hde3Kind::ConfirmPersisted => {
                let payload: crate::enrollment_v3_wire::Hde3ConfirmPersistedPayload =
                    match frame.parse_json(crate::enrollment_v3_wire::Hde3Kind::ConfirmPersisted) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                let result = self
                    .confirm_hde3_persisted(&payload, core_fingerprint.to_bytes())
                    .await;
                self.send_hde3_result(&mut send, result).await?;
            }
            crate::enrollment_v3_wire::Hde3Kind::Reconcile => {
                let payload: crate::enrollment_v3_wire::Hde3ReconcilePayload =
                    match frame.parse_json(crate::enrollment_v3_wire::Hde3Kind::Reconcile) {
                        Ok(payload) => payload,
                        Err(_) => {
                            send_hde3_rejection(&mut send, None, 1).await?;
                            return Ok(());
                        }
                    };
                if payload.validate().is_err() {
                    send_hde3_rejection(&mut send, None, 1).await?;
                    return Ok(());
                }
                let approval_id = payload
                    .approval_id()
                    .map_err(|_| RelayError::QuicProtocol {
                        reason: "HDE3 reconciliation approval is invalid",
                    })?;
                let csr_digest = decode_hex_digest(&payload.app_csr_digest)?;
                let key = hde3_issuance_key(approval_id, csr_digest);
                let result = self.reconcile_hde3_record(approval_id, key).await;
                self.send_hde3_result(&mut send, result).await?;
            }
            crate::enrollment_v3_wire::Hde3Kind::Renew => {
                send_hde3_rejection(&mut send, None, 3).await?;
            }
            _ => {
                send_hde3_rejection(&mut send, None, 3).await?;
            }
        }
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing HDE3 stream",
        })?;
        let _ = timeout(self.handshake_timeout(), send.stopped()).await;
        connection.close(0u32.into(), b"HDE3 terminal");
        Ok(())
    }

    /// Issue or resume one App certificate after HDE3 authority validation.
    async fn issue_hde3_app(
        &self,
        approval_id: [u8; 32],
        app_csr: Vec<u8>,
        app_csr_digest: [u8; 32],
        configuration_generation: u64,
    ) -> RelayResult<Result<crate::enrollment_v3_wire::Hde3ResultPayload, u16>> {
        let key = hde3_issuance_key(approval_id, app_csr_digest);
        let issuance = self
            .issuance_results
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        let now = current_epoch_seconds().map_err(|_| RelayError::ConfigurationRead)?;
        let app_id = match crate::pki::app_id_from_csr(&app_csr) {
            Ok(app_id) => app_id,
            Err(_) => return Ok(Err(4)),
        };
        let begin = match issuance.lock().await.begin_pending(
            key,
            app_id.as_str(),
            configuration_generation,
            now.saturating_add(300),
            now,
        ) {
            Ok(begin) => begin,
            Err(_) => return Ok(Err(5)),
        };
        if let IssuanceBeginResult::Existing(record) = begin {
            return Ok(match record.status() {
                IssuanceResultStatus::Issued => self.issuance_record_payload(
                    &record,
                    approval_id,
                    Some(configuration_generation),
                    false,
                ),
                IssuanceResultStatus::Rejected => {
                    crate::enrollment_v3_wire::Hde3ResultPayload::new_rejected(
                        approval_id,
                        record.rejection_code().unwrap_or(4),
                    )
                    .map_err(|_| 1)
                }
                IssuanceResultStatus::Pending => {
                    crate::enrollment_v3_wire::Hde3ResultPayload::new_pending(approval_id)
                        .map_err(|_| 1)
                }
            });
        }
        let allowlist = self
            .allowlist
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        let next_generation = allowlist
            .lock()
            .await
            .generation()
            .checked_add(1)
            .ok_or(RelayError::ResourceLimit)?;
        let issued = match crate::pki::issue_certificate(
            self.config.security(),
            current_uid()?,
            app_id.clone(),
            &app_csr,
            next_generation,
        ) {
            Ok(issued) => issued,
            Err(_) => return Ok(Err(4)),
        };
        let chain = issued.certificate_chain();
        let fingerprint = issued.fingerprint().to_bytes();
        let chain_digest = public_chain_digest(&chain);
        let not_after = issued.not_after_epoch_seconds();
        let metadata = issued
            .metadata(app_id, next_generation)
            .map_err(|_| RelayError::ConfigurationRead)?;
        issuance
            .lock()
            .await
            .attach_certificate(
                key,
                chain.clone(),
                fingerprint,
                next_generation,
                not_after,
                now,
            )
            .map_err(|_| RelayError::ConfigurationRead)?;
        let entry = match allowlist.lock().await.enroll_pending(metadata) {
            Ok(entry) => entry,
            Err(_) => return Ok(Err(5)),
        };
        let committed_generation = entry.generation();
        if issuance
            .lock()
            .await
            .mark_issued(
                key,
                chain.clone(),
                fingerprint,
                committed_generation,
                not_after,
                now,
            )
            .is_err()
        {
            return Ok(Err(5));
        }
        let payload = crate::enrollment_v3_wire::Hde3ResultPayload::new_issued(
            crate::enrollment_v3_wire::Hde3IssuedInput {
                approval_id,
                app_identity: issued.app_identity(),
                certificate_chain: &chain,
                certificate_fingerprint: fingerprint,
                certificate_chain_digest: chain_digest,
                not_after_epoch_seconds: not_after,
                configuration_generation,
                active: false,
            },
        )
        .map_err(|_| RelayError::ConfigurationRead)?;
        Ok(Ok(payload))
    }

    /// Confirm the exact issued App material and activate its protected Relay authority.
    ///
    /// # Parameters
    /// * `payload` - Core's protected-persistence confirmation metadata.
    /// * `core_identity` - Core-enrollment certificate identity authenticated by HDE3.
    ///
    /// # Returns
    /// A sanitized active/rejected result or a bounded Relay failure.
    async fn confirm_hde3_persisted(
        &self,
        payload: &crate::enrollment_v3_wire::Hde3ConfirmPersistedPayload,
        core_identity: [u8; 32],
    ) -> RelayResult<Result<crate::enrollment_v3_wire::Hde3ResultPayload, u16>> {
        if payload.validate().is_err() {
            return Ok(Err(1));
        }
        let approval_id = payload
            .approval_id()
            .map_err(|_| RelayError::QuicProtocol {
                reason: "HDE3 confirmation approval is invalid",
            })?;
        let supplied_app_identity = decode_hex_digest(&payload.app_identity)?;
        let supplied_fingerprint =
            Fingerprint::from_bytes(decode_hex_digest(&payload.issued_certificate_fingerprint)?)
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "HDE3 confirmation fingerprint is invalid",
                })?;
        let supplied_chain_digest = decode_hex_digest(&payload.issued_certificate_chain_digest)?;
        let authorization_id = hde3_authorization_id(approval_id);
        let issuance = self
            .issuance_results
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        let record = issuance
            .lock()
            .await
            .find_by_authorization_id(
                authorization_id,
                current_epoch_seconds().map_err(|_| RelayError::ConfigurationRead)?,
            )?
            .ok_or(RelayError::ConfigurationRead)?;
        let Some(expected_fingerprint) = record.fingerprint() else {
            return Ok(Err(5));
        };
        let expected_app_identity = certificate_identity_digest(record.certificate_chain());
        let expected_chain_digest = public_chain_digest(record.certificate_chain());
        if expected_app_identity != Some(supplied_app_identity)
            || expected_fingerprint != supplied_fingerprint.to_bytes()
            || expected_chain_digest != supplied_chain_digest
        {
            return Ok(Err(4));
        }
        let result = match self.issuance_record_payload(
            &record,
            approval_id,
            Some(payload.configuration_generation),
            true,
        ) {
            Ok(result) => result,
            Err(code) => return Ok(Err(code)),
        };
        let app_id = crate::enrollment::AppId::new(record.app_id().to_owned()).map_err(|_| {
            RelayError::QuicProtocol {
                reason: "HDE3 confirmation App identity is invalid",
            }
        })?;
        let bootstrap = self
            .bootstrap
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        match bootstrap
            .confirm_first_app(
                core_identity,
                approval_id,
                record.key().csr_digest(),
                payload.configuration_generation,
            )
            .await
        {
            Ok(()) | Err(BootstrapRuntimeError::NotFound) => {}
            Err(_) => return Ok(Err(5)),
        }
        let allowlist = self
            .allowlist
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        let mut allowlist = allowlist.lock().await;
        allowlist.reload()?;
        let Some((entry_state, entry_fingerprint)) = allowlist
            .entry(&app_id)
            .map(|entry| (entry.state(), entry.fingerprint()))
        else {
            return Ok(Err(5));
        };
        if entry_fingerprint != supplied_fingerprint {
            return Ok(Err(4));
        }
        match entry_state {
            AllowlistState::Pending => {
                allowlist
                    .activate(&app_id, supplied_fingerprint)
                    .map_err(|_| RelayError::ConfigurationRead)?;
            }
            AllowlistState::Active => {}
            AllowlistState::Revoked => return Ok(Err(4)),
        }
        Ok(Ok(result))
    }

    /// Reconcile a durable HDE3 issuance record without resubmitting a CSR.
    async fn reconcile_hde3_record(
        &self,
        approval_id: [u8; 32],
        key: IssuanceResultKey,
    ) -> RelayResult<Result<crate::enrollment_v3_wire::Hde3ResultPayload, u16>> {
        let issuance = self
            .issuance_results
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?;
        let record = issuance.lock().await.find(
            key,
            current_epoch_seconds().map_err(|_| RelayError::ConfigurationRead)?,
        )?;
        let Some(record) = record else {
            return Ok(Err(4));
        };
        Ok(match record.status() {
            IssuanceResultStatus::Issued => {
                self.issuance_record_payload(&record, approval_id, None, false)
            }
            IssuanceResultStatus::Pending => {
                crate::enrollment_v3_wire::Hde3ResultPayload::new_pending(approval_id)
                    .map_err(|_| 1)
            }
            IssuanceResultStatus::Rejected => {
                crate::enrollment_v3_wire::Hde3ResultPayload::new_rejected(
                    approval_id,
                    record.rejection_code().unwrap_or(4),
                )
                .map_err(|_| 1)
            }
        })
    }

    /// Convert durable public issuance data into a validated HDE3 result payload.
    ///
    /// # Parameters
    /// * `record` - Durable public certificate and binding metadata.
    /// * `approval_id` - HDE3 approval identifier returned to Core.
    /// * `configuration_generation` - Optional request generation to cross-check against the record.
    /// * `active` - Whether the App has completed protected persistence.
    ///
    /// # Returns
    /// A bounded public HDE3 result or a sanitized rejection code.
    fn issuance_record_payload(
        &self,
        record: &crate::issuance::IssuanceResultRecord,
        approval_id: [u8; 32],
        configuration_generation: Option<u64>,
        active: bool,
    ) -> Result<crate::enrollment_v3_wire::Hde3ResultPayload, u16> {
        let Some(fingerprint) = record.fingerprint() else {
            return Err(5);
        };
        let Some(record_configuration_generation) = record.configuration_generation() else {
            return Err(5);
        };
        if configuration_generation
            .is_some_and(|generation| generation != record_configuration_generation)
        {
            return Err(4);
        }
        let configuration_generation = record_configuration_generation;
        let Some(not_after) = record.not_after_epoch_seconds() else {
            return Err(5);
        };
        let identity = certificate_identity_digest(record.certificate_chain()).ok_or(5_u16)?;
        crate::enrollment_v3_wire::Hde3ResultPayload::new_issued(
            crate::enrollment_v3_wire::Hde3IssuedInput {
                approval_id,
                app_identity: identity,
                certificate_chain: record.certificate_chain(),
                certificate_fingerprint: fingerprint,
                certificate_chain_digest: public_chain_digest(record.certificate_chain()),
                not_after_epoch_seconds: not_after,
                configuration_generation,
                active,
            },
        )
        .map_err(|_| 5)
    }

    /// Send a successful or bounded HDE3 result, mapping internal failures to rejection codes.
    async fn send_hde3_result(
        &self,
        send: &mut quinn::SendStream,
        result: RelayResult<Result<crate::enrollment_v3_wire::Hde3ResultPayload, u16>>,
    ) -> RelayResult<()> {
        match result? {
            Ok(payload) => {
                let frame = crate::enrollment_v3_wire::Hde3Frame::json(
                    crate::enrollment_v3_wire::Hde3Kind::Result,
                    &payload,
                )
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "HDE3 result encoding failed",
                })?;
                timeout(
                    self.handshake_timeout(),
                    crate::enrollment_v3_wire::write_frame(send, &frame),
                )
                .await
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "HDE3 result write timeout",
                })?
                .map_err(|_| RelayError::QuicProtocol {
                    reason: "HDE3 result write failed",
                })?;
            }
            Err(code) => send_hde3_rejection(send, None, code).await?,
        }
        Ok(())
    }

    /// Historical HDE1/HDE2 handler retained only for old unit fixtures; never a production route.
    #[cfg(test)]
    #[allow(dead_code)]
    async fn serve_enrollment_connection(
        &self,
        connection: quinn::Connection,
        core_identity: Fingerprint,
    ) -> RelayResult<()> {
        let _handshake_permit =
            try_acquire(&self.enrollment_handshakes).ok_or(RelayError::ResourceLimit)?;
        let _connection_permit =
            try_acquire(&self.enrollment_connections).ok_or(RelayError::ResourceLimit)?;
        // The Relay opens the challenge stream so the challenge-first protocol cannot deadlock
        // waiting for a client frame before the client has received the challenge.
        let (mut send, mut recv) = timeout(self.handshake_timeout(), connection.open_bi())
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "enrollment control stream timeout",
            })?
            .map_err(|_| RelayError::QuicHandshake {
                reason: "enrollment control stream unavailable",
            })?;
        let mut challenge = rand::random::<[u8; 32]>();
        if challenge == [0; 32] {
            challenge[0] = 1;
        }
        let now = current_epoch_seconds().map_err(|_| RelayError::QuicHandshake {
            reason: "enrollment clock unavailable",
        })?;
        let expires_at = now
            .checked_add(self.config.enrollment().challenge_ttl_secs())
            .ok_or(RelayError::QuicHandshake {
                reason: "enrollment challenge expiry overflow",
            })?;
        let challenge_frame = EnrollmentFrame::json(
            EnrollmentFrameKind::Challenge,
            &EnrollmentChallengePayload {
                challenge,
                expires_at_epoch_seconds: expires_at,
            },
            self.config.enrollment().max_request_bytes(),
        )
        .map_err(map_enrollment_wire_error)?;
        timeout(
            self.handshake_timeout(),
            write_enrollment_frame(
                &mut send,
                &challenge_frame,
                self.config.enrollment().max_request_bytes(),
            ),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "enrollment challenge write timeout",
        })?
        .map_err(map_enrollment_wire_error)?;
        let request_frame = match timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            read_versioned_enrollment_frame(
                &mut recv,
                self.config.enrollment().max_request_bytes(),
            ),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::InvalidFrame)
                    .await;
            }
            Err(_) => {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::ResourceLimit)
                    .await;
            }
        };
        let frame = match request_frame {
            EnrollmentRequestFrame::V1(frame) => frame,
            EnrollmentRequestFrame::V2(frame) => {
                return self.serve_reconciliation_frame(&mut send, frame).await;
            }
        };
        let submission: EnrollmentSubmitPayload =
            match frame.parse_json(EnrollmentFrameKind::Submit) {
                Ok(payload) => payload,
                Err(error) => return self.reject_enrollment(&mut send, error).await,
            };
        let submission_now = current_epoch_seconds().map_err(|_| RelayError::QuicHandshake {
            reason: "enrollment clock unavailable",
        })?;
        if submission.csr.len() > self.config.enrollment().max_csr_bytes()
            || submission.challenge != challenge
            || submission_now > expires_at
            || submission.expires_at_epoch_seconds < submission_now
            || submission.expires_at_epoch_seconds > expires_at
            || submission.core_identity != core_identity.to_bytes()
        {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                .await;
        }
        let app_id = match AppId::new(submission.app_id.clone()) {
            Ok(app_id) => app_id,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let csr = match CsrMetadata::from_bytes(app_id.clone(), &submission.csr) {
            Ok(csr) => csr,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let challenge_value = match EnrollmentChallenge::from_bytes(submission.challenge) {
            Ok(challenge) => challenge,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let core_fingerprint = match Fingerprint::from_bytes(submission.core_identity) {
            Ok(fingerprint) => fingerprint,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let code_proof = match CsrDigest::from_bytes(submission.code_proof) {
            Ok(proof) => proof,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let authorization = match CoreAuthorization::new(
            core_fingerprint,
            submission.authorization_id,
            submission.pairing_id,
            submission.target_id,
            app_id.clone(),
            challenge_value,
            csr.digest(),
            code_proof,
            submission.configuration_generation,
            submission.expires_at_epoch_seconds,
        ) {
            Ok(authorization) => authorization,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let csr_digest = csr.digest();
        if EnrollmentSubmission::new(authorization, csr).is_err() {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                .await;
        }
        let Some(issuance_results) = &self.issuance_results else {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::PersistenceFailed)
                .await;
        };
        let key = match IssuanceResultKey::new(submission.authorization_id, *csr_digest.as_bytes())
        {
            Ok(key) => key,
            Err(_) => {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                    .await;
            }
        };
        let begin = match issuance_results.lock().await.begin_pending(
            key,
            app_id.as_str(),
            submission.configuration_generation,
            submission.expires_at_epoch_seconds,
            submission_now,
        ) {
            Ok(begin) => begin,
            Err(error) => {
                return self
                    .reject_enrollment(&mut send, map_issuance_error(&error))
                    .await;
            }
        };
        match begin {
            IssuanceBeginResult::Created(_) => {}
            IssuanceBeginResult::Existing(record) => match record.status() {
                IssuanceResultStatus::Issued | IssuanceResultStatus::Rejected => {
                    return self.send_reconciled_record(&mut send, &record).await;
                }
                IssuanceResultStatus::Pending => {
                    // A duplicate Submit must never mint another certificate. The pending outcome
                    // is intentionally surfaced as a closed response so Core uses HDE v2.
                    return self.finish_unknown_enrollment(&mut send);
                }
            },
        }
        let Some(allowlist) = &self.allowlist else {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::PersistenceFailed)
                .await;
        };
        let expected_uid = current_uid().map_err(|_| RelayError::QuicAuthentication)?;
        let next_generation = allowlist.lock().await.generation().checked_add(1).ok_or(
            RelayError::ListenerStartup {
                reason: "allowlist generation overflow",
            },
        )?;
        let issued = match issue_certificate(
            self.config.security(),
            expected_uid,
            app_id.clone(),
            &submission.csr,
            next_generation,
        ) {
            Ok(issued) => issued,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let metadata = match issued.metadata(app_id.clone(), next_generation) {
            Ok(metadata) => metadata,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let fingerprint = metadata.fingerprint().to_bytes();
        let not_after = metadata.not_after_epoch_seconds();
        let certificate_chain = issued.certificate_chain();
        if issuance_results
            .lock()
            .await
            .attach_certificate(
                key,
                certificate_chain.clone(),
                fingerprint,
                next_generation,
                not_after,
                submission_now,
            )
            .is_err()
        {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::PersistenceFailed)
                .await;
        }
        let allowlist_result = { allowlist.lock().await.enroll(metadata) };
        let committed_generation = match allowlist_result {
            Ok(entry) => entry.generation(),
            Err(crate::enrollment::EnrollmentError::DuplicateEnrollment) => {
                let snapshot = allowlist.lock().await.snapshot();
                let app = AppId::new(app_id.as_str().to_owned()).map_err(|_| {
                    RelayError::QuicProtocol {
                        reason: "issued App identity is invalid",
                    }
                })?;
                let Some(entry) = snapshot.entry(&app) else {
                    let _ = issuance_results.lock().await.mark_rejected(
                        key,
                        EnrollmentWireError::AuthorizationRejected as u16,
                        submission_now,
                    );
                    return self
                        .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                        .await;
                };
                if entry.state() != crate::enrollment::AllowlistState::Active
                    || entry.fingerprint().to_bytes() != fingerprint
                {
                    let _ = issuance_results.lock().await.mark_rejected(
                        key,
                        EnrollmentWireError::AuthorizationRejected as u16,
                        submission_now,
                    );
                    return self
                        .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                        .await;
                }
                entry.generation()
            }
            Err(_) => return self.finish_unknown_enrollment(&mut send),
        };
        if issuance_results
            .lock()
            .await
            .mark_issued(
                key,
                certificate_chain.clone(),
                fingerprint,
                committed_generation,
                not_after,
                submission_now,
            )
            .is_err()
        {
            return self.finish_unknown_enrollment(&mut send);
        }
        let response = EnrollmentFrame::json(
            EnrollmentFrameKind::Issued,
            &EnrollmentIssuedPayload {
                certificate_chain,
                fingerprint,
                allowlist_generation: committed_generation,
                not_after_epoch_seconds: not_after,
            },
            self.config.enrollment().max_request_bytes(),
        )
        .map_err(map_enrollment_wire_error)?;
        timeout(
            self.handshake_timeout(),
            write_enrollment_frame(
                &mut send,
                &response,
                self.config.enrollment().max_request_bytes(),
            ),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "enrollment response write timeout",
        })?
        .map_err(map_enrollment_wire_error)?;
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing enrollment connection",
        })?;
        // Wait for the peer to acknowledge the terminal response before closing the QUIC
        // connection; an immediate CONNECTION_CLOSE can discard the just-issued certificate.
        let _ = timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            send.stopped(),
        )
        .await;
        connection.close(0u32.into(), b"enrollment complete");
        Ok(())
    }

    /// Historical HDE2 fixture handler; production recovery uses HDE3.
    #[cfg(test)]
    #[allow(dead_code)]
    async fn serve_reconciliation_frame(
        &self,
        send: &mut quinn::SendStream,
        frame: ReconciliationFrame,
    ) -> RelayResult<()> {
        let request: ReconcilePayload = frame
            .parse_json(ReconciliationFrameKind::Reconcile)
            .map_err(|_| RelayError::QuicProtocol {
                reason: "reconciliation request is invalid",
            })?;
        let key =
            IssuanceResultKey::new(request.authorization_id, request.csr_digest).map_err(|_| {
                RelayError::QuicProtocol {
                    reason: "reconciliation binding is invalid",
                }
            })?;
        let now = current_epoch_seconds().map_err(|_| RelayError::QuicHandshake {
            reason: "enrollment clock unavailable",
        })?;
        let mut result = self
            .issuance_results
            .as_ref()
            .ok_or(RelayError::ConfigurationRead)?
            .lock()
            .await
            .reconcile(key, now)?;
        let pending_material = result.as_ref().and_then(|record| {
            if record.status() != IssuanceResultStatus::Pending
                || record.certificate_chain().is_empty()
            {
                return None;
            }
            Some((
                record.key(),
                record.app_id().to_owned(),
                record.certificate_chain().to_vec(),
                record.fingerprint()?,
                record.allowlist_generation()?,
                record.not_after_epoch_seconds()?,
            ))
        });
        if let Some((pending_key, app_id, chain, fingerprint, generation, not_after)) =
            pending_material
        {
            let app = AppId::new(app_id).map_err(|_| RelayError::ConfigurationRead)?;
            let allowlist_matches = if let Some(allowlist) = &self.allowlist {
                let mut allowlist = allowlist.lock().await;
                allowlist.reload()?;
                let snapshot = allowlist.snapshot();
                snapshot.entry(&app).is_some_and(|entry| {
                    entry.state() == crate::enrollment::AllowlistState::Active
                        && entry.fingerprint().to_bytes() == fingerprint
                        && entry.generation() == generation
                })
            } else {
                false
            };
            if allowlist_matches {
                result = Some(
                    self.issuance_results
                        .as_ref()
                        .ok_or(RelayError::ConfigurationRead)?
                        .lock()
                        .await
                        .mark_issued(pending_key, chain, fingerprint, generation, not_after, now)?,
                );
            }
        }
        let payload = reconciliation_payload(result.as_ref())?;
        payload.validate().map_err(|_| RelayError::QuicProtocol {
            reason: "reconciliation result is invalid",
        })?;
        let response = ReconciliationFrame::json(
            ReconciliationFrameKind::Result,
            &payload,
            self.config.enrollment().max_request_bytes(),
        )
        .map_err(|_| RelayError::QuicProtocol {
            reason: "reconciliation result exceeds bounds",
        })?;
        timeout(
            self.handshake_timeout(),
            write_reconciliation_frame(
                send,
                &response,
                self.config.enrollment().max_request_bytes(),
            ),
        )
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "reconciliation response write timeout",
        })?
        .map_err(|_| RelayError::QuicProtocol {
            reason: "reconciliation response write failed",
        })?;
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing reconciliation connection",
        })?;
        let _ = timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            send.stopped(),
        )
        .await;
        Ok(())
    }

    /// Historical HDE1 fixture helper; production HDE3 uses typed Result frames.
    #[cfg(test)]
    #[allow(dead_code)]
    fn finish_unknown_enrollment(&self, send: &mut quinn::SendStream) -> RelayResult<()> {
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing unresolved enrollment connection",
        })
    }

    /// Historical HDE1 fixture helper; production HDE3 uses its own result path.
    #[cfg(test)]
    #[allow(dead_code)]
    async fn send_reconciled_record(
        &self,
        send: &mut quinn::SendStream,
        record: &crate::issuance::IssuanceResultRecord,
    ) -> RelayResult<()> {
        match record.status() {
            IssuanceResultStatus::Issued => {
                let (Some(fingerprint), Some(allowlist_generation), Some(not_after_epoch_seconds)) = (
                    record.fingerprint(),
                    record.allowlist_generation(),
                    record.not_after_epoch_seconds(),
                ) else {
                    return self
                        .reject_enrollment(send, EnrollmentWireError::PersistenceFailed)
                        .await;
                };
                let frame = EnrollmentFrame::json(
                    EnrollmentFrameKind::Issued,
                    &EnrollmentIssuedPayload {
                        certificate_chain: record.certificate_chain().to_vec(),
                        fingerprint,
                        allowlist_generation,
                        not_after_epoch_seconds,
                    },
                    self.config.enrollment().max_request_bytes(),
                )
                .map_err(map_enrollment_wire_error)?;
                timeout(
                    self.handshake_timeout(),
                    write_enrollment_frame(
                        send,
                        &frame,
                        self.config.enrollment().max_request_bytes(),
                    ),
                )
                .await
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "reconciled issuance response write timeout",
                })?
                .map_err(map_enrollment_wire_error)?;
                send.finish().map_err(|_| RelayError::QuicProtocol {
                    reason: "finishing reconciled enrollment connection",
                })?;
                Ok(())
            }
            IssuanceResultStatus::Rejected => {
                let code = record
                    .rejection_code()
                    .ok_or(RelayError::ConfigurationRead)?;
                let frame = EnrollmentFrame::json(
                    EnrollmentFrameKind::Rejected,
                    &EnrollmentRejectedPayload { code },
                    self.config.enrollment().max_request_bytes(),
                )
                .map_err(map_enrollment_wire_error)?;
                timeout(
                    self.handshake_timeout(),
                    write_enrollment_frame(
                        send,
                        &frame,
                        self.config.enrollment().max_request_bytes(),
                    ),
                )
                .await
                .map_err(|_| RelayError::QuicHandshake {
                    reason: "reconciled rejection response write timeout",
                })?
                .map_err(map_enrollment_wire_error)?;
                send.finish().map_err(|_| RelayError::QuicProtocol {
                    reason: "finishing reconciled rejection connection",
                })?;
                Ok(())
            }
            IssuanceResultStatus::Pending => self.finish_unknown_enrollment(send),
        }
    }

    /// Historical HDE1 fixture helper; production HDE3 uses fixed rejection frames.
    #[cfg(test)]
    #[allow(dead_code)]
    async fn reject_enrollment(
        &self,
        send: &mut quinn::SendStream,
        error: EnrollmentWireError,
    ) -> RelayResult<()> {
        let frame = EnrollmentFrame::json(
            EnrollmentFrameKind::Rejected,
            &EnrollmentRejectedPayload { code: error as u16 },
            self.config.enrollment().max_request_bytes(),
        )
        .map_err(map_enrollment_wire_error)?;
        let _ = timeout(
            self.handshake_timeout(),
            write_enrollment_frame(send, &frame, self.config.enrollment().max_request_bytes()),
        )
        .await;
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing enrollment rejection",
        })?;
        // Preserve the bounded rejection payload before the terminal connection close.
        let _ = timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            send.stopped(),
        )
        .await;
        Ok(())
    }

    async fn finish_session_control(
        &self,
        registry: &Arc<Mutex<SessionRegistry>>,
        controls: &SessionTaskControls,
        handle: u16,
        done: &Arc<Notify>,
    ) {
        controls.lock().await.remove(&handle);
        registry.lock().await.close(handle);
        done.notify_waiters();
    }

    /// Owns one HDQS stream, validates its authority, opens the Unix socket and bridges opaque bytes.
    async fn serve_session_stream(
        &self,
        connection: quinn::Connection,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        registry: Arc<Mutex<SessionRegistry>>,
        session_controls: SessionTaskControls,
    ) -> RelayResult<()> {
        let binding = match timeout(self.handshake_timeout(), read_hdqs_binding(&mut recv)).await {
            Ok(Ok(binding)) => binding,
            Ok(Err(_)) | Err(_) => {
                // A malformed session preface has no trustworthy handle to clean selectively;
                // return the fixed wire rejection, then close the physical connection so every
                // prepared/active authority is dropped together with the connection registry.
                let epoch = registry.lock().await.connection_epoch();
                let result = self.reject_invalid_stream(&mut send, epoch).await;
                connection.close(0u32.into(), b"invalid HDQS binding");
                return result;
            }
        };
        let response = registry.lock().await.accept_active(&binding);
        if response.kind == crate::quic_wire::HdqsKind::Rejected {
            return self
                .reject_session(&mut send, &registry, &binding, response, false)
                .await;
        }

        // Register cancellation immediately after authority acceptance. A concurrent close or
        // lease expiry can therefore cancel the task before Unix connection or HDQS acceptance.
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let done = Arc::new(Notify::new());
        session_controls.lock().await.insert(
            binding.session_handle,
            SessionTaskControl {
                cancel: cancel_tx,
                done: done.clone(),
            },
        );
        if !registry.lock().await.active_bound_exact(&binding) {
            self.finish_session_control(
                &registry,
                &session_controls,
                binding.session_handle,
                &done,
            )
            .await;
            return Ok(());
        }

        let socket_path = self.socket_path(&binding.session);
        let connector =
            match current_uid().and_then(|uid| UnixSocketConnector::new(socket_path, uid)) {
                Ok(connector) => connector,
                Err(_) => {
                    let rejection = HdqsResponse::rejected(
                        HdqsReason::SocketUnavailable,
                        response.connection_epoch,
                    );
                    let result = self
                        .reject_session(&mut send, &registry, &binding, rejection, true)
                        .await;
                    self.finish_session_control(
                        &registry,
                        &session_controls,
                        binding.session_handle,
                        &done,
                    )
                    .await;
                    return result;
                }
            };
        let unix = tokio::select! {
            _ = &mut cancel_rx => {
                self.finish_session_control(&registry, &session_controls, binding.session_handle, &done).await;
                return Ok(());
            }
            result = timeout(self.handshake_timeout(), connector.connect()) => match result {
                Ok(Ok(stream)) => stream,
                _ => {
                    let rejection = HdqsResponse::rejected(HdqsReason::SocketUnavailable, response.connection_epoch);
                    let result = self.reject_session(&mut send, &registry, &binding, rejection, true).await;
                    self.finish_session_control(&registry, &session_controls, binding.session_handle, &done).await;
                    return result;
                }
            }
        };

        let encoded_accept = response.encode().map_err(|_| RelayError::QuicProtocol {
            reason: "HDQS acceptance encoding failed",
        })?;
        let write_accept = tokio::select! {
            _ = &mut cancel_rx => {
                self.finish_session_control(&registry, &session_controls, binding.session_handle, &done).await;
                return Ok(());
            }
            result = send.write_all(&encoded_accept) => result.map_err(|_| RelayError::QuicProtocol { reason: "writing HDQS acceptance" }),
        };
        if let Err(error) = write_accept {
            self.finish_session_control(
                &registry,
                &session_controls,
                binding.session_handle,
                &done,
            )
            .await;
            return Err(error);
        }

        if !registry.lock().await.active_bound_exact(&binding) {
            // SESSION_CLOSE or expiry may have won while the acceptance bytes were in flight;
            // never start opaque forwarding for an authority that is no longer owned.
            self.finish_session_control(
                &registry,
                &session_controls,
                binding.session_handle,
                &done,
            )
            .await;
            return Ok(());
        }

        // Keep checking the live registry while the bridge runs so a renewed heartbeat extends
        // the lease, but an expired/closed authority stops opaque forwarding within one tick.
        let mut lease_tick = tokio::time::interval(Duration::from_secs(1));
        let mut bridge_task = Box::pin(bridge::run(
            QuicBiStream { recv, send },
            unix,
            BridgeLimits::new(
                self.config.limits().buffer_bytes(),
                Duration::from_secs(self.config.limits().idle_timeout_secs()),
            )?,
        ));
        loop {
            tokio::select! {
                result = &mut bridge_task => {
                    let _ = result;
                    break;
                }
                _ = &mut cancel_rx => break,
                _ = lease_tick.tick() => {
                    if !registry.lock().await.active_bound_exact(&binding) {
                        break;
                    }
                }
            }
        }
        self.finish_session_control(&registry, &session_controls, binding.session_handle, &done)
            .await;
        Ok(())
    }

    /// Send a fixed invalid-frame rejection before closing a malformed session connection.
    async fn reject_invalid_stream(
        &self,
        send: &mut quinn::SendStream,
        connection_epoch: u64,
    ) -> RelayResult<()> {
        let encoded = HdqsResponse::rejected(HdqsReason::InvalidFrame, connection_epoch)
            .encode()
            .map_err(|_| RelayError::QuicProtocol {
                reason: "invalid HDQS rejection encoding failed",
            })?;
        timeout(self.handshake_timeout(), send.write_all(&encoded))
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "invalid HDQS rejection write timeout",
            })?
            .map_err(|_| RelayError::QuicProtocol {
                reason: "writing invalid HDQS rejection",
            })?;
        send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing invalid HDQS rejection",
        })?;
        let _ = timeout(self.handshake_timeout(), send.stopped()).await;
        Ok(())
    }

    /// Send one fixed HDQS rejection and always release its exact authority handle.
    async fn reject_session(
        &self,
        send: &mut quinn::SendStream,
        registry: &Arc<Mutex<SessionRegistry>>,
        binding: &HdqsBinding,
        response: HdqsResponse,
        close_bound: bool,
    ) -> RelayResult<()> {
        // Revoke only the authority owned by this task before any peer-controlled write. A
        // duplicate/rejected stream may not close an already-bound sibling authority.
        if close_bound {
            registry.lock().await.close_exact(binding);
        } else {
            registry.lock().await.close_unbound_if_exact(binding);
        }
        let encoded = response.encode().map_err(|_| RelayError::QuicProtocol {
            reason: "HDQS rejection encoding failed",
        })?;
        let write_result = timeout(self.handshake_timeout(), send.write_all(&encoded))
            .await
            .map_err(|_| RelayError::QuicHandshake {
                reason: "HDQS rejection write timeout",
            })
            .and_then(|result| {
                result.map_err(|_| RelayError::QuicProtocol {
                    reason: "writing HDQS rejection",
                })
            });
        let finish_result = send.finish().map_err(|_| RelayError::QuicProtocol {
            reason: "finishing HDQS rejection",
        });
        write_result?;
        finish_result?;
        Ok(())
    }

    fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.config.limits().handshake_timeout_secs())
    }

    fn socket_path(&self, session: &crate::quic_wire::SessionName) -> PathBuf {
        if let Some(path) = &self.socket_override {
            return path.clone();
        }
        let root = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("herdr");
        if session.as_str() == "default" {
            root.join("herdr.sock")
        } else {
            root.join("sessions")
                .join(session.as_str())
                .join("herdr.sock")
        }
    }

    /// Sends the uncorrelated GOAWAY control frame used to begin a bounded read-only drain.
    async fn send_go_away(&self, send: &mut quinn::SendStream) -> RelayResult<()> {
        send_control_frame(
            send,
            HdqmFrame {
                kind: HdqmKind::GoAway,
                request_id: [0; 16],
                payload: Vec::new(),
            },
        )
        .await
    }

    /// Waits until a drain deadline, or forever while the connection remains open.
    async fn wait_for_drain_deadline(deadline: Option<Instant>) {
        match deadline {
            Some(deadline) => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    /// Clones only immutable server state for a spawned connection task.
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            relay_generation: self.relay_generation,
            relay_identity: self.relay_identity,
            ca_generation: self.ca_generation,
            endpoint: None,
            connections: Arc::clone(&self.connections),
            pre_auth_handshakes: Arc::clone(&self.pre_auth_handshakes),
            bootstrap_handshakes: Arc::clone(&self.bootstrap_handshakes),
            bootstrap_connections: Arc::clone(&self.bootstrap_connections),
            enrollment_handshakes: Arc::clone(&self.enrollment_handshakes),
            enrollment_connections: Arc::clone(&self.enrollment_connections),
            issuance_results: self.issuance_results.clone(),
            allowlist: self.allowlist.clone(),
            drain_tx: self.drain_tx.clone(),
            bootstrap: self.bootstrap.clone(),
            socket_override: self.socket_override.clone(),
        }
    }
}

/// Builds one fixed HDB1 rejection frame without retaining payload material.
fn hdb1_rejection_frame(code: u16) -> RelayResult<crate::bootstrap_wire::Hdb1Frame> {
    let payload = crate::bootstrap_wire::Hdb1RejectedPayload::new(code).map_err(|_| {
        RelayError::QuicProtocol {
            reason: "HDB1 rejection is invalid",
        }
    })?;
    crate::bootstrap_wire::Hdb1Frame::json(crate::bootstrap_wire::Hdb1Kind::Rejected, &payload)
        .map_err(|_| RelayError::QuicProtocol {
            reason: "HDB1 rejection is invalid",
        })
}

/// Send one fixed HDB1 rejection before closing the bootstrap connection.
async fn send_hdb1_rejection(send: &mut quinn::SendStream, code: u16) -> RelayResult<()> {
    let frame = hdb1_rejection_frame(code)?;
    timeout(
        QRM_HANDSHAKE_TIMEOUT,
        crate::bootstrap_wire::write_frame(send, &frame),
    )
    .await
    .map_err(|_| RelayError::QuicHandshake {
        reason: "HDB1 rejection write timeout",
    })?
    .map_err(|_| RelayError::QuicProtocol {
        reason: "HDB1 rejection write failed",
    })
}

/// Send one fixed HDE3 rejection or a correlated rejected Result.
async fn send_hde3_rejection(
    send: &mut quinn::SendStream,
    approval_id: Option<[u8; 32]>,
    code: u16,
) -> RelayResult<()> {
    let (kind, frame) = if let Some(approval_id) = approval_id {
        let payload = crate::enrollment_v3_wire::Hde3ResultPayload::new_rejected(approval_id, code)
            .map_err(|_| RelayError::QuicProtocol {
                reason: "HDE3 rejection is invalid",
            })?;
        (
            crate::enrollment_v3_wire::Hde3Kind::Result,
            crate::enrollment_v3_wire::Hde3Frame::json(
                crate::enrollment_v3_wire::Hde3Kind::Result,
                &payload,
            ),
        )
    } else {
        let payload = crate::enrollment_v3_wire::Hde3RejectedPayload::new(code).map_err(|_| {
            RelayError::QuicProtocol {
                reason: "HDE3 rejection is invalid",
            }
        })?;
        (
            crate::enrollment_v3_wire::Hde3Kind::Rejected,
            crate::enrollment_v3_wire::Hde3Frame::json(
                crate::enrollment_v3_wire::Hde3Kind::Rejected,
                &payload,
            ),
        )
    };
    let _ = kind;
    let frame = frame.map_err(|_| RelayError::QuicProtocol {
        reason: "HDE3 rejection is invalid",
    })?;
    timeout(
        QRM_HANDSHAKE_TIMEOUT,
        crate::enrollment_v3_wire::write_frame(send, &frame),
    )
    .await
    .map_err(|_| RelayError::QuicHandshake {
        reason: "HDE3 rejection write timeout",
    })?
    .map_err(|_| RelayError::QuicProtocol {
        reason: "HDE3 rejection write failed",
    })
}

/// Return the remaining absolute lifetime for one HDB1 connection.
fn remaining_bootstrap_time(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Bound one bootstrap operation by both the connection deadline and its local timeout.
fn bounded_bootstrap_timeout(deadline: Instant, operation: Duration) -> Duration {
    remaining_bootstrap_time(deadline).min(operation)
}

/// Map the bounded bootstrap runtime error to a nonzero HDB1/HDE3 rejection code.
fn bootstrap_rejection_code(error: BootstrapRuntimeError) -> u16 {
    match error {
        BootstrapRuntimeError::InvalidField => 1,
        BootstrapRuntimeError::AuthorityMismatch => 4,
        BootstrapRuntimeError::WorkspaceUnavailable | BootstrapRuntimeError::PersistenceFailed => 5,
        BootstrapRuntimeError::CapacityExhausted => 2,
        BootstrapRuntimeError::PeerRateLimited => 2,
        BootstrapRuntimeError::AlreadyActive => 3,
        BootstrapRuntimeError::Expired => 7,
        BootstrapRuntimeError::CodeMismatch => 8,
        BootstrapRuntimeError::CodeRateLimited => 6,
        BootstrapRuntimeError::NotFound => 4,
    }
}

/// Decode one lowercase hexadecimal 32-byte digest from an HDE3 payload.
fn decode_hex_digest(value: &str) -> RelayResult<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(RelayError::QuicProtocol {
            reason: "HDE3 digest is invalid",
        });
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[index] = high << 4 | low;
    }
    if output == [0; 32] {
        return Err(RelayError::QuicProtocol {
            reason: "HDE3 digest is empty",
        });
    }
    Ok(output)
}

/// Decode one lowercase hexadecimal nibble without echoing the source value.
fn hex_nibble(value: u8) -> RelayResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(RelayError::QuicProtocol {
            reason: "HDE3 digest is invalid",
        }),
    }
}

/// Derive the fixed 16-byte issuance key from the HDE3 approval and CSR digest.
fn hde3_issuance_key(approval_id: [u8; 32], csr_digest: [u8; 32]) -> IssuanceResultKey {
    IssuanceResultKey::new(hde3_authorization_id(approval_id), csr_digest)
        .expect("nonzero HDE3 issuance key")
}

/// Derive a non-secret issuance correlation identifier from a 32-byte HDE3 approval.
fn hde3_authorization_id(approval_id: [u8; 32]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"herdr-dog-hde3-issuance-id-v1");
    digest.update(approval_id);
    let bytes: [u8; 32] = digest.finalize().into();
    let mut output = [0_u8; 16];
    output.copy_from_slice(&bytes[..16]);
    if output == [0; 16] {
        output[0] = 1;
    }
    output
}

/// Compute a length-delimited digest for a public certificate chain.
fn public_chain_digest(chain: &[Vec<u8>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for certificate in chain {
        digest.update((certificate.len() as u64).to_be_bytes());
        digest.update(certificate);
    }
    digest.finalize().into()
}

/// Derive the App identity from the leaf certificate's canonical SubjectPublicKeyInfo.
fn certificate_identity_digest(chain: &[Vec<u8>]) -> Option<[u8; 32]> {
    let leaf = chain.first()?;
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf).ok()?;
    Some(Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into())
}

fn perform_stable_latest_update(config: RelayConfig) -> RelayResult<()> {
    let updater = FixedSourceUpdater::new(config.update().clone())?;
    let _lock = updater.acquire_lock()?;
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        _ => {
            return Err(RelayError::Update {
                operation: "running stable-latest update",
                reason: "unsupported operating system",
            });
        }
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => {
            return Err(RelayError::Update {
                operation: "running stable-latest update",
                reason: "unsupported architecture",
            });
        }
    };
    let (archive, checksums) = updater.download_latest(os, arch)?;
    updater.verify_checksum(&archive, &checksums)?;
    let staged = updater.extract_verified(&archive)?;
    updater.verify_staged_startup(&staged)?;
    let installed = std::env::current_exe().map_err(|_| RelayError::Update {
        operation: "running stable-latest update",
        reason: "current executable path is unavailable",
    })?;
    let backup = installed.with_extension("previous");
    updater.replace_binary(&staged, &installed, &backup)
}

/// Historical HDE1/HDE2 fixture mapping; production uses HDE3 errors.
#[cfg(test)]
#[allow(dead_code)]
fn map_issuance_error(error: &RelayError) -> EnrollmentWireError {
    match error {
        RelayError::ResourceLimit => EnrollmentWireError::ResourceLimit,
        RelayError::QuicProtocol { .. } => EnrollmentWireError::AuthorizationRejected,
        _ => EnrollmentWireError::PersistenceFailed,
    }
}

/// Historical HDE2 fixture mapping; production recovery uses HDE3 Result.
#[cfg(test)]
#[allow(dead_code)]
fn reconciliation_payload(
    record: Option<&crate::issuance::IssuanceResultRecord>,
) -> RelayResult<ReconciliationResultPayload> {
    let Some(record) = record else {
        return Ok(ReconciliationResultPayload {
            status: ReconciliationStatus::Rejected,
            certificate_chain: Vec::new(),
            fingerprint: None,
            allowlist_generation: None,
            not_after_epoch_seconds: None,
            rejection_code: Some(EnrollmentWireError::AuthorizationRejected as u16),
        });
    };
    match record.status() {
        IssuanceResultStatus::Pending => Ok(ReconciliationResultPayload {
            status: ReconciliationStatus::Pending,
            certificate_chain: Vec::new(),
            fingerprint: None,
            allowlist_generation: None,
            not_after_epoch_seconds: None,
            rejection_code: None,
        }),
        IssuanceResultStatus::Issued => {
            let (Some(fingerprint), Some(allowlist_generation), Some(not_after_epoch_seconds)) = (
                record.fingerprint(),
                record.allowlist_generation(),
                record.not_after_epoch_seconds(),
            ) else {
                return Err(RelayError::ConfigurationRead);
            };
            Ok(ReconciliationResultPayload {
                status: ReconciliationStatus::Issued,
                certificate_chain: record.certificate_chain().to_vec(),
                fingerprint: Some(fingerprint),
                allowlist_generation: Some(allowlist_generation),
                not_after_epoch_seconds: Some(not_after_epoch_seconds),
                rejection_code: None,
            })
        }
        IssuanceResultStatus::Rejected => Ok(ReconciliationResultPayload {
            status: ReconciliationStatus::Rejected,
            certificate_chain: Vec::new(),
            fingerprint: None,
            allowlist_generation: None,
            not_after_epoch_seconds: None,
            rejection_code: record.rejection_code(),
        }),
    }
}

/// Historical HDE1/HDE2 fixture mapping; production dispatch uses HDB1/HDE3.
#[cfg(test)]
#[allow(dead_code)]
fn map_enrollment_wire_error(error: EnrollmentWireError) -> RelayError {
    match error {
        EnrollmentWireError::FrameTooLarge => RelayError::QuicProtocol {
            reason: "enrollment frame exceeds bound",
        },
        EnrollmentWireError::ResourceLimit => RelayError::ResourceLimit,
        EnrollmentWireError::InvalidOrder => RelayError::QuicProtocol {
            reason: "enrollment operation order is invalid",
        },
        EnrollmentWireError::AuthorizationRejected => RelayError::QuicAuthentication,
        EnrollmentWireError::PersistenceFailed => RelayError::ConfigurationRead,
        EnrollmentWireError::InvalidFrame => RelayError::QuicProtocol {
            reason: "enrollment frame is invalid",
        },
    }
}

/// Reads one complete bounded HDQM frame from a QUIC receive stream.
async fn read_control_frame(recv: &mut quinn::RecvStream) -> RelayResult<HdqmFrame> {
    let mut header = [0_u8; crate::quic_wire::HDQM_HEADER_BYTES];
    recv.read_exact(&mut header)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "control frame header read failed",
        })?;
    let payload_len = u32::from_be_bytes([header[23], header[24], header[25], header[26]]) as usize;
    if payload_len > crate::quic_wire::QRM_MAX_CONTROL_PAYLOAD_BYTES {
        return Err(RelayError::QuicProtocol {
            reason: "control frame exceeds bound",
        });
    }
    let mut bytes = Vec::with_capacity(header.len() + payload_len);
    bytes.extend_from_slice(&header);
    let mut payload = vec![0_u8; payload_len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "control frame payload read failed",
        })?;
    bytes.extend_from_slice(&payload);
    HdqmFrame::decode(&bytes).map_err(|_| RelayError::QuicProtocol {
        reason: "control frame decode failed",
    })
}

/// Reads one control frame under the configured connection deadline.
async fn read_control_frame_timed(
    recv: &mut quinn::RecvStream,
    deadline: Duration,
) -> RelayResult<HdqmFrame> {
    timeout(deadline, read_control_frame(recv))
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "control frame timeout",
        })?
}

/// Owns the control receive stream so select cancellation cannot discard partial frame bytes.
fn spawn_control_reader(
    mut recv: quinn::RecvStream,
    deadline: Duration,
) -> mpsc::Receiver<RelayResult<HdqmFrame>> {
    let (sender, receiver) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let result = read_control_frame_timed(&mut recv, deadline).await;
            let terminal = result.is_err();
            if sender.send(result).await.is_err() || terminal {
                break;
            }
        }
    });
    receiver
}

async fn send_control_frame(send: &mut quinn::SendStream, frame: HdqmFrame) -> RelayResult<()> {
    let bytes = frame.encode().map_err(|_| RelayError::QuicProtocol {
        reason: "control frame encode failed",
    })?;
    timeout(QRM_HANDSHAKE_TIMEOUT, send.write_all(&bytes))
        .await
        .map_err(|_| RelayError::QuicHandshake {
            reason: "control frame write timeout",
        })?
        .map_err(|_| RelayError::QuicProtocol {
            reason: "writing control frame",
        })
}

/// Reads the variable-length HDQS binding preface before any Herdr bytes.
async fn read_hdqs_binding(recv: &mut quinn::RecvStream) -> RelayResult<HdqsBinding> {
    let mut prefix = [0_u8; 33];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "HDQS prefix read failed",
        })?;
    let name_len = usize::from(prefix[32]);
    if name_len == 0 || name_len > crate::quic_wire::QRM_MAX_SESSION_NAME_BYTES {
        return Err(RelayError::QuicProtocol {
            reason: "HDQS session name length invalid",
        });
    }
    let mut bytes = Vec::with_capacity(33 + name_len + 64);
    bytes.extend_from_slice(&prefix);
    let mut remainder = vec![0_u8; name_len + 64];
    recv.read_exact(&mut remainder)
        .await
        .map_err(|_| RelayError::QuicProtocol {
            reason: "HDQS authority read failed",
        })?;
    bytes.extend_from_slice(&remainder);
    HdqsBinding::decode(&bytes).map_err(|_| RelayError::QuicProtocol {
        reason: "HDQS binding decode failed",
    })
}

/// Acquires one connection permit without waiting behind an unbounded queue.
fn try_acquire(semaphore: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    semaphore.clone().try_acquire_owned().ok()
}

/// Returns the negotiated ALPN without accepting unrecognized protocol namespaces.
fn negotiated_alpn(connection: &quinn::Connection) -> RelayResult<Vec<u8>> {
    let data = connection
        .handshake_data()
        .ok_or(RelayError::QuicHandshake {
            reason: "QUIC handshake data unavailable",
        })?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| RelayError::QuicHandshake {
            reason: "QUIC handshake data type is invalid",
        })?;
    data.protocol.ok_or(RelayError::QuicHandshake {
        reason: "QUIC ALPN was not negotiated",
    })
}

/// Computes the leaf certificate fingerprint used by the persistent App allowlist.
fn peer_certificate_fingerprint(connection: &quinn::Connection) -> RelayResult<Fingerprint> {
    let identity = connection
        .peer_identity()
        .ok_or(RelayError::QuicAuthentication)?;
    let certificates = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| RelayError::QuicAuthentication)?;
    let leaf = certificates.first().ok_or(RelayError::QuicAuthentication)?;
    let digest = Sha256::digest(leaf.as_ref());
    Fingerprint::from_bytes(digest.into()).map_err(|_| RelayError::QuicAuthentication)
}

/// Verifies that the presented client chain contains the dedicated Core enrollment anchor.
fn peer_certificate_matches_anchor(
    connection: &quinn::Connection,
    anchor_path: &Path,
) -> RelayResult<bool> {
    let anchor_bytes = read_protected_file(
        anchor_path,
        current_uid()?,
        ProtectedFileKind::Public,
        MAX_PUBLIC_MATERIAL_BYTES,
    )?;
    let anchors = load_certificates_from_bytes(&anchor_bytes)?;
    let identity = connection
        .peer_identity()
        .ok_or(RelayError::QuicAuthentication)?;
    let certificates = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| RelayError::QuicAuthentication)?;
    Ok(certificate_chain_matches_anchor(&certificates, &anchors))
}

/// Requires the presented leaf's actual issuer to match and verify against the Core anchor.
fn certificate_chain_matches_anchor(
    certificates: &[rustls::pki_types::CertificateDer<'static>],
    anchors: &[rustls::pki_types::CertificateDer<'static>],
) -> bool {
    let Some(leaf) = certificates.first() else {
        return false;
    };
    let Ok((_, leaf_certificate)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return false;
    };
    certificates.iter().skip(1).any(|issuer| {
        let Ok((_, issuer_certificate)) = x509_parser::parse_x509_certificate(issuer.as_ref())
        else {
            return false;
        };
        if leaf_certificate.tbs_certificate.issuer != issuer_certificate.subject
            || leaf_certificate
                .verify_signature(Some(issuer_certificate.public_key()))
                .is_err()
        {
            return false;
        }
        anchors
            .iter()
            .any(|anchor| Sha256::digest(issuer.as_ref()) == Sha256::digest(anchor.as_ref()))
    })
}

/// Parses a bounded PEM certificate chain from already protected bytes.
fn load_certificates_from_bytes(
    bytes: &[u8],
) -> RelayResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "trusted Core enrollment CA is invalid",
        })
}

fn build_server_config(config: &RelayConfig) -> RelayResult<quinn::ServerConfig> {
    let certs = load_certificates(config.security().server_certificate())?;
    let key = load_private_key(config.security().server_private_key())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "TLS 1.3 provider configuration failed",
        })?;
    let mut tls = match config.security().mode() {
        SecurityMode::Verified => {
            let mut roots = load_client_roots(config.security().trusted_client_ca())?;
            if config.enrollment().enabled() {
                for certificate in
                    load_certificates(config.security().trusted_core_enrollment_ca())?
                {
                    roots
                        .add(certificate)
                        .map_err(|_| RelayError::TlsConfiguration {
                            reason: "trusted Core enrollment CA is invalid",
                        })?;
                }
            }
            let verifier = if config.enrollment().enabled() {
                // HDB1 is server-authenticated; normal QRM and HDE3 still reject missing or
                // wrong certificates at their application admission boundaries below.
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .allow_unauthenticated()
                    .build()
                    .map_err(|_| RelayError::TlsConfiguration {
                        reason: "client CA verifier construction failed",
                    })?
            } else {
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|_| RelayError::TlsConfiguration {
                        reason: "client CA verifier construction failed",
                    })?
            };
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|_| RelayError::TlsConfiguration {
                    reason: "server certificate configuration failed",
                })?
        }
        SecurityMode::DevelopmentUnverified => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| RelayError::TlsConfiguration {
                reason: "development certificate configuration failed",
            })?,
    };
    tls.alpn_protocols = if config.enrollment().enabled() {
        vec![
            QRM_RELAY_ALPN.to_vec(),
            QRM_ENROLLMENT_ALPN.to_vec(),
            QRM_BOOTSTRAP_ALPN.to_vec(),
        ]
    } else {
        vec![QRM_RELAY_ALPN.to_vec()]
    };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| {
        RelayError::TlsConfiguration {
            reason: "QUIC TLS adapter construction failed",
        }
    })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport =
        Arc::get_mut(&mut server_config.transport).ok_or(RelayError::ListenerStartup {
            reason: "QUIC transport configuration is not uniquely owned",
        })?;
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(config.limits().idle_timeout_secs())
                .try_into()
                .map_err(|_| RelayError::InvalidConfiguration {
                    field: "limits.idle_timeout_secs",
                    reason: "idle timeout cannot be represented by QUIC",
                })?,
        ))
        .keep_alive_interval(Some(Duration::from_secs(
            (config.limits().idle_timeout_secs() / 3).max(1),
        )))
        .max_concurrent_bidi_streams(
            (config.limits().max_sessions_per_connection() as u64 + 1)
                .try_into()
                .map_err(|_| RelayError::InvalidConfiguration {
                    field: "limits.max_sessions_per_connection",
                    reason: "session limit cannot be represented by QUIC",
                })?,
        );
    Ok(server_config)
}

/// Computes the Relay certificate fingerprint used by the application hello.
fn load_relay_identity(config: &RelayConfig) -> RelayResult<[u8; 32]> {
    let certificates = load_certificates(config.security().server_certificate())?;
    let certificate = certificates.first().ok_or(RelayError::TlsConfiguration {
        reason: "server certificate chain is empty",
    })?;
    let digest = Sha256::digest(certificate.as_ref());
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(&digest);
    Ok(identity)
}

/// Loads all PEM certificates only after protected-file ownership and mode validation.
fn load_certificates(path: &Path) -> RelayResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    // Read the certificate chain through the same protected-file boundary as enrollment anchors.
    let bytes = read_protected_file(
        path,
        current_uid()?,
        ProtectedFileKind::Public,
        MAX_PUBLIC_MATERIAL_BYTES,
    )
    .map_err(|_| RelayError::TlsConfiguration {
        reason: "certificate material is unsafe",
    })?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "certificate PEM is invalid",
        })
}

/// Loads one PEM private key only after owner-only protected-file validation.
fn load_private_key(path: &Path) -> RelayResult<rustls::pki_types::PrivateKeyDer<'static>> {
    // Private key bytes remain transient after the protected reader rejects unsafe paths and modes.
    let bytes = read_protected_file(
        path,
        current_uid()?,
        ProtectedFileKind::Private,
        MAX_PRIVATE_MATERIAL_BYTES,
    )
    .map_err(|_| RelayError::TlsConfiguration {
        reason: "private-key material is unsafe",
    })?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(bytes.as_slice()))
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "private-key PEM is invalid",
        })?
        .ok_or(RelayError::TlsConfiguration {
            reason: "private-key PEM is empty",
        })
}

/// Loads a bounded trusted Core client CA store.
fn load_client_roots(path: &Path) -> RelayResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in load_certificates(path)? {
        roots
            .add(certificate)
            .map_err(|_| RelayError::TlsConfiguration {
                reason: "trusted client CA is invalid",
            })?;
    }
    if roots.is_empty() {
        return Err(RelayError::TlsConfiguration {
            reason: "trusted client CA is empty",
        });
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::{
        enrollment_wire::{
            EnrollmentChallengePayload, EnrollmentFrame, EnrollmentFrameKind,
            EnrollmentIssuedPayload, EnrollmentSubmitPayload, read_frame as read_enrollment_frame,
            write_frame as write_enrollment_frame,
        },
        quic_wire::{
            DeviceHelloAck, HdqmFrame, HdqmKind, HdqsBinding, HdqsResponse, SessionName,
            SessionOpenAck, SessionOpenRequest, SessionPrepareAck, SessionPrepareRequest,
        },
        reconciliation_wire::{
            ReconcilePayload, ReconciliationFrame, ReconciliationFrameKind,
            ReconciliationResultPayload, ReconciliationStatus,
            read_frame as read_reconciliation_frame, write_frame as write_reconciliation_frame,
        },
    };
    use rcgen::{
        BasicConstraints, Certificate as RcgenCertificate, CertificateParams, CertifiedIssuer,
        DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    fn config() -> RelayConfig {
        RelayConfig::from_toml_str(
            r#"
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
"#,
        )
        .expect("valid config")
    }

    async fn open_test_session(
        connection: &quinn::Connection,
        control_send: &mut quinn::SendStream,
        control_recv: &mut quinn::RecvStream,
        name: &str,
        fingerprint: [u8; 32],
        id: u8,
    ) -> (u16, [u8; 32], quinn::SendStream, quinn::RecvStream) {
        let prepare = SessionPrepareRequest {
            session: SessionName::new(name).expect("session"),
            expected_fingerprint: fingerprint,
            configuration_generation: 1,
        };
        send_control_frame(
            control_send,
            HdqmFrame {
                kind: HdqmKind::SessionPrepare,
                request_id: [id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                payload: prepare.encode().expect("prepare encode"),
            },
        )
        .await
        .expect("prepare");
        let prepare_frame = read_control_frame(control_recv).await.expect("prepare ack");
        let prepare_ack =
            SessionPrepareAck::decode(&prepare_frame.payload).expect("prepare payload");
        let open = SessionOpenRequest {
            session: prepare_ack.session.clone(),
            fingerprint: prepare_ack.fingerprint,
            configuration_generation: prepare_ack.configuration_generation,
            relay_generation: prepare_ack.relay_generation,
            connection_epoch: prepare_ack.connection_epoch,
            token: prepare_ack.token,
        };
        send_control_frame(
            control_send,
            HdqmFrame {
                kind: HdqmKind::SessionOpen,
                request_id: [id + 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                payload: open.encode().expect("open encode"),
            },
        )
        .await
        .expect("open");
        let open_frame = read_control_frame(control_recv).await.expect("open ack");
        let open_ack = SessionOpenAck::decode(&open_frame.payload).expect("open payload");
        let (mut session_send, mut session_recv) =
            connection.open_bi().await.expect("session stream");
        let binding = HdqsBinding {
            session_handle: open_ack.session_handle,
            configuration_generation: open_ack.configuration_generation,
            relay_generation: open_ack.relay_generation,
            connection_epoch: open_ack.connection_epoch,
            session: open_ack.session,
            fingerprint: open_ack.fingerprint,
            token: open_ack.token,
        };
        session_send
            .write_all(&binding.encode().expect("binding encode"))
            .await
            .expect("binding");
        let mut response = [0_u8; 20];
        session_recv
            .read_exact(&mut response)
            .await
            .expect("HDQS response");
        assert_eq!(
            HdqsResponse::decode(&response).expect("response").kind as u8,
            2
        );
        (
            open_ack.session_handle,
            open_ack.token,
            session_send,
            session_recv,
        )
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_shutdown_sends_goaway_and_blocks_new_sessions]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_shutdown_sends_goaway_and_blocks_new_sessions() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-drain-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nca_generation=7\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            server_cert_path.display(),
        ))
        .expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 7, root.join("missing.sock"))
            .await
            .expect("bind server");
        let address = server.local_addr().expect("server address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (endpoint, connection, mut control_send, mut control_recv) =
            connect_dev_client(server_cert.cert.der().to_vec(), address).await;

        shutdown_tx.send(()).expect("request drain");
        let go_away = tokio::time::timeout(
            Duration::from_secs(1),
            read_control_frame(&mut control_recv),
        )
        .await
        .expect("GOAWAY deadline")
        .expect("GOAWAY frame");
        assert_eq!(go_away.kind, HdqmKind::GoAway);
        assert_eq!(go_away.request_id, [0; 16]);
        assert!(go_away.payload.is_empty());

        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionPrepare,
                request_id: [8; 16],
                payload: SessionPrepareRequest {
                    session: SessionName::new("default").expect("session"),
                    expected_fingerprint: [3; 32],
                    configuration_generation: 1,
                }
                .encode()
                .expect("prepare"),
            },
        )
        .await
        .expect("prepare during drain");
        let rejection = tokio::time::timeout(
            Duration::from_secs(1),
            read_control_frame(&mut control_recv),
        )
        .await
        .expect("drain rejection deadline")
        .expect("drain rejection");
        assert_eq!(rejection.kind, HdqmKind::ErrorResponse);
        let rejection = HdqsResponse::decode(&rejection.payload).expect("rejection payload");
        assert_eq!(rejection.reason, HdqsReason::ConnectionClosing);

        connection.close(0u32.into(), b"drain test complete");
        endpoint.close(0u32.into(), b"drain test complete");
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server drain deadline")
            .expect("server task")
            .expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_quic_three_session_network_isolated]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_quic_three_session_network_isolated() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        // Keep the canonical Darwin Unix socket path below SUN_LEN with a short test directory.
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("t{}{}", std::process::id(), nonce % 1_000_000));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let socket_path = root.join("herdr.sock");
        let unix_listener = UnixListener::bind(&socket_path).expect("unix listener");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let unix_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = unix_listener.accept().await.expect("accept unix");
                tokio::spawn(async move {
                    let mut byte = [0_u8; 1];
                    if stream.read_exact(&mut byte).await.is_ok() {
                        let _ = stream.write_all(&byte).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nca_generation=7\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(), server_key_path.display(), server_cert_path.display()
        )).expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 11, socket_path)
            .await
            .expect("bind server");
        let expected_ca_generation = server.ca_generation();
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert.cert.der().to_vec()))
            .expect("root");
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![QRM_RELAY_ALPN.to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("client tls"),
        ));
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        let (mut control_send, mut control_recv) = connection.open_bi().await.expect("control");
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::DeviceHello,
                request_id: [1; 16],
                payload: Vec::new(),
            },
        )
        .await
        .expect("hello");
        let hello_ack = read_control_frame(&mut control_recv)
            .await
            .expect("hello ack");
        // The served hello must carry the generation loaded from Relay configuration.
        let hello_ack = DeviceHelloAck::decode(&hello_ack.payload).expect("hello ack payload");
        assert_eq!(hello_ack.ca_generation, expected_ca_generation);
        let mut streams = Vec::new();
        for (index, name) in ["default", "work", "review"].into_iter().enumerate() {
            streams.push(
                open_test_session(
                    &connection,
                    &mut control_send,
                    &mut control_recv,
                    name,
                    [index as u8 + 3; 32],
                    index as u8 + 2,
                )
                .await,
            );
        }
        let mut heartbeat = vec![3_u8];
        for (handle, token, _, _) in &streams {
            heartbeat.extend_from_slice(&handle.to_be_bytes());
            heartbeat.extend_from_slice(token);
        }
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::Heartbeat,
                request_id: [44; 16],
                payload: heartbeat,
            },
        )
        .await
        .expect("heartbeat");
        assert_eq!(
            read_control_frame(&mut control_recv)
                .await
                .expect("heartbeat ack")
                .kind,
            HdqmKind::Heartbeat
        );
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::Heartbeat,
                request_id: [47; 16],
                payload: {
                    let mut payload = vec![1_u8];
                    payload.extend_from_slice(&streams[1].0.to_be_bytes());
                    payload.extend_from_slice(&[0_u8; 32]);
                    payload
                },
            },
        )
        .await
        .expect("stale heartbeat");
        let stale = read_control_frame(&mut control_recv)
            .await
            .expect("stale heartbeat response");
        assert_eq!(stale.kind, HdqmKind::ErrorResponse);
        let stale_response =
            HdqsResponse::decode(&stale.payload).expect("stale heartbeat response payload");
        assert_eq!(stale_response.reason, HdqsReason::TokenMismatch);
        for (index, (_, _, send, recv)) in streams.iter_mut().enumerate() {
            send.write_all(&[b'a' + index as u8])
                .await
                .expect("session write");
            let mut echoed = [0_u8; 1];
            recv.read_exact(&mut echoed).await.expect("session echo");
            assert_eq!(echoed[0], b'a' + index as u8);
        }
        let (close_handle, _, mut closed_send, mut closed_recv) = streams.remove(0);
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionClose,
                request_id: [45; 16],
                payload: close_handle.to_be_bytes().to_vec(),
            },
        )
        .await
        .expect("session close");
        assert_eq!(
            read_control_frame(&mut control_recv)
                .await
                .expect("session close ack")
                .kind,
            HdqmKind::SessionClosed
        );
        let mut closed = [0_u8; 1];
        let closed_result =
            tokio::time::timeout(Duration::from_secs(1), closed_recv.read_exact(&mut closed)).await;
        assert!(
            closed_result.is_err() || closed_result.as_ref().is_ok_and(|result| result.is_err())
        );
        let _ = closed_send.write_all(b"x").await;
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::GoAway,
                request_id: [46; 16],
                payload: Vec::new(),
            },
        )
        .await
        .expect("go away");
        connection.close(0u32.into(), b"test complete");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        unix_task.await.expect("Unix task");
        fs::remove_dir_all(root).expect("cleanup");
    }

    async fn connect_dev_client(
        server_cert_der: Vec<u8>,
        address: SocketAddr,
    ) -> (
        quinn::Endpoint,
        quinn::Connection,
        quinn::SendStream,
        quinn::RecvStream,
    ) {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert_der))
            .expect("root");
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![QRM_RELAY_ALPN.to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("client TLS"),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send_control_frame(
            &mut send,
            HdqmFrame {
                kind: HdqmKind::DeviceHello,
                request_id: [1; 16],
                payload: Vec::new(),
            },
        )
        .await
        .expect("hello");
        assert_eq!(
            read_control_frame(&mut recv).await.expect("hello ack").kind,
            HdqmKind::DeviceHelloAck
        );
        (endpoint, connection, send, recv)
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_relay_update_is_rejected_before_execution]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_relay_update_is_rejected_before_execution() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-update-reject-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            server_cert_path.display()
        ))
        .expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 16, root.join("missing.sock"))
            .await
            .expect("bind server");
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (_endpoint, connection, mut control_send, mut control_recv) =
            connect_dev_client(server_cert.cert.der().to_vec(), address).await;
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::RelayUpdate,
                request_id: [9; 16],
                payload: Vec::new(),
            },
        )
        .await
        .expect("relay.update frame");
        tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("unsupported relay.update must close the connection");
        let no_response = tokio::time::timeout(
            Duration::from_millis(100),
            read_control_frame(&mut control_recv),
        )
        .await;
        assert!(
            no_response.is_err() || matches!(no_response, Ok(Err(_))),
            "unsupported relay.update must not receive an execution response"
        );
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_malformed_hdqs_gets_fixed_rejection]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_malformed_hdqs_gets_fixed_rejection() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-malformed-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            server_cert_path.display()
        ))
        .expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 15, root.join("missing.sock"))
            .await
            .expect("bind server");
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (_endpoint, connection, mut control_send, mut control_recv) =
            connect_dev_client(server_cert.cert.der().to_vec(), address).await;
        let prepare = SessionPrepareRequest {
            session: SessionName::new("default").expect("session"),
            expected_fingerprint: [1; 32],
            configuration_generation: 1,
        };
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionPrepare,
                request_id: [2; 16],
                payload: prepare.encode().expect("prepare"),
            },
        )
        .await
        .expect("prepare");
        let prepare_ack = SessionPrepareAck::decode(
            &read_control_frame(&mut control_recv)
                .await
                .expect("prepare ack")
                .payload,
        )
        .expect("prepare payload");
        let open = SessionOpenRequest {
            session: prepare_ack.session.clone(),
            fingerprint: prepare_ack.fingerprint,
            configuration_generation: prepare_ack.configuration_generation,
            relay_generation: prepare_ack.relay_generation,
            connection_epoch: prepare_ack.connection_epoch,
            token: prepare_ack.token,
        };
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionOpen,
                request_id: [3; 16],
                payload: open.encode().expect("open"),
            },
        )
        .await
        .expect("open");
        let open_ack = SessionOpenAck::decode(
            &read_control_frame(&mut control_recv)
                .await
                .expect("open ack")
                .payload,
        )
        .expect("open payload");
        let (mut session_send, mut session_recv) = connection.open_bi().await.expect("session");
        session_send
            .write_all(b"bad")
            .await
            .expect("malformed binding");
        session_send.finish().expect("finish malformed binding");
        let mut response = [0_u8; crate::quic_wire::HDQS_RESPONSE_BYTES];
        session_recv
            .read_exact(&mut response)
            .await
            .expect("fixed rejection");
        let response = HdqsResponse::decode(&response).expect("rejection payload");
        assert_eq!(response.reason, HdqsReason::InvalidFrame);
        assert_eq!(response.connection_epoch, open_ack.connection_epoch);
        tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("malformed binding must close the connection");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_prepare_capacity_is_session_scoped]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_prepare_capacity_is_session_scoped() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-capacity-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=1\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            server_cert_path.display()
        ))
        .expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 14, root.join("missing.sock"))
            .await
            .expect("bind server");
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (_endpoint, connection, mut control_send, mut control_recv) =
            connect_dev_client(server_cert.cert.der().to_vec(), address).await;
        for (request_id, session) in [([2; 16], "first"), ([3; 16], "second")] {
            let prepare = SessionPrepareRequest {
                session: SessionName::new(session).expect("session"),
                expected_fingerprint: [1; 32],
                configuration_generation: 1,
            };
            send_control_frame(
                &mut control_send,
                HdqmFrame {
                    kind: HdqmKind::SessionPrepare,
                    request_id,
                    payload: prepare.encode().expect("prepare"),
                },
            )
            .await
            .expect("prepare");
            let response = read_control_frame(&mut control_recv)
                .await
                .expect("prepare response");
            if session == "first" {
                assert_eq!(response.kind, HdqmKind::SessionPrepareAck);
                SessionPrepareAck::decode(&response.payload).expect("prepare ack");
            } else {
                assert_eq!(response.kind, HdqmKind::ErrorResponse);
                let error = HdqsResponse::decode(&response.payload).expect("capacity response");
                assert_eq!(error.reason, HdqsReason::CapacityExhausted);
            }
        }
        connection.close(0u32.into(), b"capacity test complete");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_socket_rejection_is_fixed]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_socket_rejection_is_fixed() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-reject-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        let missing_socket = root.join("missing.sock");
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(), server_key_path.display(), server_cert_path.display()
        )).expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 13, missing_socket)
            .await
            .expect("bind server");
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let (_endpoint, connection, mut control_send, mut control_recv) =
            connect_dev_client(server_cert.cert.der().to_vec(), address).await;
        let prepare = SessionPrepareRequest {
            session: SessionName::new("default").expect("session"),
            expected_fingerprint: [3; 32],
            configuration_generation: 1,
        };
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionPrepare,
                request_id: [2; 16],
                payload: prepare.encode().expect("prepare"),
            },
        )
        .await
        .expect("prepare");
        let prepare_ack = SessionPrepareAck::decode(
            &read_control_frame(&mut control_recv)
                .await
                .expect("prepare ack")
                .payload,
        )
        .expect("prepare payload");
        let open = SessionOpenRequest {
            session: prepare_ack.session.clone(),
            fingerprint: prepare_ack.fingerprint,
            configuration_generation: prepare_ack.configuration_generation,
            relay_generation: prepare_ack.relay_generation,
            connection_epoch: prepare_ack.connection_epoch,
            token: prepare_ack.token,
        };
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionOpen,
                request_id: [3; 16],
                payload: open.encode().expect("open"),
            },
        )
        .await
        .expect("open");
        let open_ack = SessionOpenAck::decode(
            &read_control_frame(&mut control_recv)
                .await
                .expect("open ack")
                .payload,
        )
        .expect("open payload");
        let (mut session_send, mut session_recv) = connection.open_bi().await.expect("session");
        let binding = HdqsBinding {
            session_handle: open_ack.session_handle,
            configuration_generation: open_ack.configuration_generation,
            relay_generation: open_ack.relay_generation,
            connection_epoch: open_ack.connection_epoch,
            session: open_ack.session,
            fingerprint: open_ack.fingerprint,
            token: open_ack.token,
        };
        session_send
            .write_all(&binding.encode().expect("binding"))
            .await
            .expect("binding");
        let mut response = [0_u8; 20];
        session_recv
            .read_exact(&mut response)
            .await
            .expect("rejection response");
        assert_eq!(
            HdqsResponse::decode(&response).expect("decode").reason,
            HdqsReason::SocketUnavailable
        );
        connection.close(0u32.into(), b"test complete");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::qrm_quic_control_and_session_bridge]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_quic_control_and_session_bridge() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        // Keep the canonical Darwin Unix socket path below SUN_LEN with a short test directory.
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("q{}{}", std::process::id(), nonce % 1_000_000));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_der = server_cert.cert.der().to_vec();
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        let client_cert =
            rcgen::generate_simple_self_signed(vec!["client".to_owned()]).expect("client cert");
        let client_cert_path = root.join("client.pem");
        let allowlist_path = root.join("allowlist.json");
        write_test_material(&server_cert_path, server_cert.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server_cert.signing_key.serialize_pem().as_bytes(),
        );
        write_test_material(&client_cert_path, client_cert.cert.pem().as_bytes());
        let socket_path = root.join("herdr.sock");
        let test_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let unix_listener = UnixListener::bind(&socket_path).expect("unix listener");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let unix_task = tokio::spawn(async move {
            let (mut stream, _) = unix_listener.accept().await.expect("accept unix");
            let mut request = [0_u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("read Herdr bytes");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("write Herdr bytes");
            stream.shutdown().await.expect("close Unix stream");
        });
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={test_port}\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[enrollment]\nenabled=false\nallowlist_path=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            client_cert_path.display(),
            allowlist_path.display(),
        )).expect("config");
        // Populate the mandatory verified-QRM allowlist with this test client's exact leaf hash.
        let client_fingerprint =
            Fingerprint::from_bytes(Sha256::digest(client_cert.cert.der()).into())
                .expect("client fingerprint");
        let now = current_epoch_seconds().expect("test epoch");
        let certificate = crate::enrollment::CertificateMetadata::new(
            AppId::new("bridge-client").expect("App ID"),
            client_fingerprint,
            1,
            1,
            now,
            now.checked_add(3600).expect("test expiry"),
        )
        .expect("allowlist certificate metadata");
        let mut allowlist = PersistentAllowlist::open(&allowlist_path, current_uid().expect("UID"))
            .expect("allowlist");
        allowlist.enroll(certificate).expect("allowlist enrollment");
        drop(allowlist);
        let server = QuicRelayServer::bind_with_socket_path(config, 7, socket_path)
            .await
            .expect("bind server");
        let address = server.local_addr().expect("server address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert_der))
            .expect("root");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(Arc::new(roots))
            .with_client_auth_cert(
                vec![CertificateDer::from(client_cert.cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    client_cert.signing_key.serialize_der(),
                )),
            )
            .expect("client auth");
        client_tls.alpn_protocols = vec![QRM_RELAY_ALPN.to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("QUIC TLS"),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        let (mut control_send, mut control_recv) =
            connection.open_bi().await.expect("control stream");
        let hello_id = [1; 16];
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::DeviceHello,
                request_id: hello_id,
                payload: Vec::new(),
            },
        )
        .await
        .expect("hello");
        assert_eq!(
            read_control_frame(&mut control_recv)
                .await
                .expect("hello ack")
                .kind,
            HdqmKind::DeviceHelloAck
        );
        let prepare = SessionPrepareRequest {
            session: SessionName::new("default").expect("session"),
            expected_fingerprint: [3; 32],
            configuration_generation: 1,
        };
        let prepare_id = [2; 16];
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionPrepare,
                request_id: prepare_id,
                payload: prepare.encode().expect("prepare encode"),
            },
        )
        .await
        .expect("prepare");
        let prepare_frame = read_control_frame(&mut control_recv)
            .await
            .expect("prepare ack");
        let prepare_ack =
            SessionPrepareAck::decode(&prepare_frame.payload).expect("prepare payload");
        let open = SessionOpenRequest {
            session: prepare_ack.session.clone(),
            fingerprint: prepare_ack.fingerprint,
            configuration_generation: prepare_ack.configuration_generation,
            relay_generation: prepare_ack.relay_generation,
            connection_epoch: prepare_ack.connection_epoch,
            token: prepare_ack.token,
        };
        let open_id = [3; 16];
        send_control_frame(
            &mut control_send,
            HdqmFrame {
                kind: HdqmKind::SessionOpen,
                request_id: open_id,
                payload: open.encode().expect("open encode"),
            },
        )
        .await
        .expect("open");
        let open_frame = read_control_frame(&mut control_recv)
            .await
            .expect("open ack");
        let open_ack = SessionOpenAck::decode(&open_frame.payload).expect("open payload");
        let (mut session_send, mut session_recv) =
            connection.open_bi().await.expect("session stream");
        let binding = HdqsBinding {
            session_handle: open_ack.session_handle,
            configuration_generation: open_ack.configuration_generation,
            relay_generation: open_ack.relay_generation,
            connection_epoch: open_ack.connection_epoch,
            session: open_ack.session,
            fingerprint: open_ack.fingerprint,
            token: open_ack.token,
        };
        session_send
            .write_all(&binding.encode().expect("binding encode"))
            .await
            .expect("binding");
        let mut response = [0_u8; 20];
        session_recv
            .read_exact(&mut response)
            .await
            .expect("HDQS response");
        assert_eq!(
            HdqsResponse::decode(&response).expect("response").kind as u8,
            2
        );
        session_send.write_all(b"ping").await.expect("send Herdr");
        let mut pong = [0_u8; 4];
        session_recv
            .read_exact(&mut pong)
            .await
            .expect("read Herdr");
        assert_eq!(&pong, b"pong");
        connection.close(0u32.into(), b"test complete");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        unix_task.await.expect("Unix task");
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::enrollment_anchor_rejects_chain_stuffing]
    #[test]
    fn enrollment_anchor_rejects_chain_stuffing() {
        let app = rcgen::generate_simple_self_signed(vec!["app".to_owned()]).expect("app");
        let core_anchor =
            rcgen::generate_simple_self_signed(vec!["core".to_owned()]).expect("core");
        let certificates = vec![
            CertificateDer::from(app.cert.der().to_vec()),
            CertificateDer::from(core_anchor.cert.der().to_vec()),
        ];
        let anchors = vec![CertificateDer::from(core_anchor.cert.der().to_vec())];
        assert!(!super::certificate_chain_matches_anchor(
            &certificates,
            &anchors
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_mode_rejects_missing_client_certificate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-mtls-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let client_ca = test_ca("client-ca");
        let (unlisted_client, unlisted_client_key) =
            test_client_certificate("unlisted-client", &client_ca);
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        let client_ca_path = root.join("client-ca.pem");
        let allowlist_path = root.join("allowlist.json");
        write_test_material(&server_cert_path, server.cert.pem().as_bytes());
        write_test_material(
            &server_key_path,
            server.signing_key.serialize_pem().as_bytes(),
        );
        write_test_material(&client_ca_path, client_ca.pem().as_bytes());
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[enrollment]\nenabled=false\nallowlist_path=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(),
            server_key_path.display(),
            client_ca_path.display(),
            allowlist_path.display(),
        )).expect("verified config");
        let server_cert_der = server.cert.der().to_vec();
        let server = QuicRelayServer::bind(config, 9)
            .await
            .expect("bind verified server");
        let address = server.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_cert_der.clone()))
            .expect("root");
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![QRM_RELAY_ALPN.to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).expect("client tls"),
        ));
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        let result = endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await;
        match result {
            Err(_) => {}
            Ok(connection) => {
                let closed =
                    tokio::time::timeout(std::time::Duration::from_secs(1), connection.closed())
                        .await
                        .expect("verified server must close an unauthenticated client");
                assert!(!matches!(closed, quinn::ConnectionError::LocallyClosed));
            }
        }
        // A trusted mTLS chain alone is insufficient: an unlisted App closes before QRM use.
        let mut unlisted_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("unlisted endpoint");
        unlisted_endpoint.set_default_client_config(test_client_config(
            server_cert_der.clone(),
            vec![unlisted_client.der().to_vec(), client_ca.der().to_vec()],
            Some(unlisted_client_key.serialize_der()),
            QRM_RELAY_ALPN,
        ));
        let unlisted_connection = unlisted_endpoint
            .connect(address, "localhost")
            .expect("unlisted connect")
            .await
            .expect("unlisted TLS transport");
        tokio::time::timeout(Duration::from_secs(1), unlisted_connection.closed())
            .await
            .expect("unlisted App must close before QRM use");
        unlisted_endpoint.close(0u32.into(), b"unlisted App test complete");

        let mut wrong_roots = rustls::RootCertStore::empty();
        wrong_roots
            .add(CertificateDer::from(server_cert_der))
            .expect("wrong-alpn root");
        let mut wrong_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(Arc::new(wrong_roots))
        .with_no_client_auth();
        wrong_tls.alpn_protocols = vec![b"wrong-relay/1".to_vec()];
        let wrong_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(wrong_tls).expect("wrong ALPN TLS"),
        ));
        let mut wrong_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("wrong endpoint");
        wrong_endpoint.set_default_client_config(wrong_config);
        let wrong_result = wrong_endpoint
            .connect(address, "localhost")
            .expect("wrong connect")
            .await;
        match wrong_result {
            Err(_) => {}
            Ok(connection) => {
                let closed =
                    tokio::time::timeout(std::time::Duration::from_secs(1), connection.closed())
                        .await
                        .expect("wrong ALPN must close");
                assert!(!matches!(closed, quinn::ConnectionError::LocallyClosed));
            }
        }
        let _ = shutdown_tx.send(());
        task.await.expect("server task").expect("server result");
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Build a protected test file with the owner-only mode required by Relay configuration.
    fn write_test_material(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("material");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("material mode");
    }

    // TEST:relay/src/quic_server.rs[tests::verified_tls_loaders_reject_unsafe_server_material]
    #[test]
    fn verified_tls_loaders_reject_unsafe_server_material() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temporary root")
            .join(format!(
                "qrm-unsafe-tls-material-{}-{nonce}",
                std::process::id()
            ));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let identity =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("identity");
        let client_ca = test_ca("loader-client-ca");
        let certificate = root.join("server.pem");
        let private_key = root.join("server.key");
        let trusted_client_ca = root.join("client-ca.pem");
        let allowlist = root.join("allowlist.json");
        write_test_material(&certificate, identity.cert.pem().as_bytes());
        write_test_material(
            &private_key,
            identity.signing_key.serialize_pem().as_bytes(),
        );
        write_test_material(&trusted_client_ca, client_ca.pem().as_bytes());
        let config_for = |server_certificate: &Path,
                          server_private_key: &Path,
                          client_ca: &Path| {
            RelayConfig::from_toml_str(&format!(
                "[listener]\nlisten_address=\"127.0.0.1\"\nport=18743\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[enrollment]\nenabled=false\nallowlist_path=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
                server_certificate.display(),
                server_private_key.display(),
                client_ca.display(),
                allowlist.display(),
            ))
            .expect("configuration")
        };
        assert!(
            build_server_config(&config_for(&certificate, &private_key, &trusted_client_ca,))
                .is_ok()
        );

        fs::set_permissions(&certificate, fs::Permissions::from_mode(0o666))
            .expect("unsafe certificate mode");
        assert!(
            build_server_config(&config_for(&certificate, &private_key, &trusted_client_ca,))
                .is_err()
        );
        write_test_material(&certificate, identity.cert.pem().as_bytes());

        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644))
            .expect("unsafe private-key mode");
        assert!(
            build_server_config(&config_for(&certificate, &private_key, &trusted_client_ca,))
                .is_err()
        );
        write_test_material(
            &private_key,
            identity.signing_key.serialize_pem().as_bytes(),
        );

        fs::set_permissions(&trusted_client_ca, fs::Permissions::from_mode(0o666))
            .expect("unsafe client CA mode");
        assert!(
            build_server_config(&config_for(&certificate, &private_key, &trusted_client_ca,))
                .is_err()
        );
        write_test_material(&trusted_client_ca, client_ca.pem().as_bytes());

        let certificate_link = root.join("server-link.pem");
        symlink(&certificate, &certificate_link).expect("certificate symlink");
        assert!(
            build_server_config(&config_for(
                &certificate_link,
                &private_key,
                &trusted_client_ca,
            ))
            .is_err()
        );

        let unsafe_parent = root.join("unsafe-parent");
        fs::create_dir(&unsafe_parent).expect("unsafe parent");
        let unsafe_ca = unsafe_parent.join("client-ca.pem");
        write_test_material(&unsafe_ca, client_ca.pem().as_bytes());
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))
            .expect("unsafe parent mode");
        assert!(build_server_config(&config_for(&certificate, &private_key, &unsafe_ca)).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    /// Create a disposable CA issuer whose private key never leaves the test process.
    fn test_ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key")).expect("CA")
    }

    /// Issue a disposable client certificate from a test CA with the requested client usage.
    fn test_client_certificate(
        name: &str,
        issuer: &CertifiedIssuer<'_, KeyPair>,
    ) -> (RcgenCertificate, KeyPair) {
        let key = KeyPair::generate().expect("client key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.signed_by(&key, issuer).expect("client certificate");
        (certificate, key)
    }

    /// Build a TLS 1.3 QUIC client config with optional mTLS identity and one ALPN.
    fn test_client_config(
        server_certificate: Vec<u8>,
        client_chain: Vec<Vec<u8>>,
        client_key: Option<Vec<u8>>,
        alpn: &[u8],
    ) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_certificate))
            .expect("server root");
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(Arc::new(roots));
        let mut tls = match client_key {
            Some(client_key) => builder
                .with_client_auth_cert(
                    client_chain.into_iter().map(CertificateDer::from).collect(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key)),
                )
                .expect("client identity"),
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![alpn.to_vec()];
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client TLS"),
        ))
    }

    /// Query one unknown authorization through the real HDE version-two reconciliation path.
    async fn reconcile_unknown_test(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("reconciliation connect")
            .await
            .expect("reconciliation TLS");
        let (mut send, mut recv) = connection.accept_bi().await.expect("reconciliation stream");
        let challenge = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("enrollment challenge");
        assert_eq!(challenge.kind, EnrollmentFrameKind::Challenge);
        let request = ReconciliationFrame::json(
            ReconciliationFrameKind::Reconcile,
            &ReconcilePayload {
                authorization_id: [41; 16],
                csr_digest: [42; 32],
            },
            65_536,
        )
        .expect("reconciliation request");
        write_reconciliation_frame(&mut send, &request, 65_536)
            .await
            .expect("reconciliation request write");
        let response = read_reconciliation_frame(&mut recv, 65_536)
            .await
            .expect("reconciliation response");
        assert_eq!(response.kind, ReconciliationFrameKind::Result);
        let payload: ReconciliationResultPayload = response
            .parse_json(ReconciliationFrameKind::Result)
            .expect("reconciliation result payload");
        payload.validate().expect("valid reconciliation result");
        assert_eq!(payload.status, ReconciliationStatus::Rejected);
        assert!(payload.rejection_code.is_some());
        connection.close(0u32.into(), b"reconciliation complete");
        endpoint.close(0u32.into(), b"reconciliation complete");
    }

    /// Replay one durable issued record through the real HDE version-two path.
    async fn reconcile_issued_test(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
        authorization_id: [u8; 16],
        csr_digest: [u8; 32],
        expected_chain: Vec<Vec<u8>>,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("issued reconciliation connect")
            .await
            .expect("issued reconciliation TLS");
        let (mut send, mut recv) = connection.accept_bi().await.expect("reconciliation stream");
        let challenge = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("enrollment challenge");
        assert_eq!(challenge.kind, EnrollmentFrameKind::Challenge);
        let request = ReconciliationFrame::json(
            ReconciliationFrameKind::Reconcile,
            &ReconcilePayload {
                authorization_id,
                csr_digest,
            },
            65_536,
        )
        .expect("reconciliation request");
        write_reconciliation_frame(&mut send, &request, 65_536)
            .await
            .expect("reconciliation request write");
        let response = read_reconciliation_frame(&mut recv, 65_536)
            .await
            .expect("reconciliation response");
        let payload: ReconciliationResultPayload = response
            .parse_json(ReconciliationFrameKind::Result)
            .expect("reconciliation result payload");
        payload.validate().expect("valid reconciliation result");
        assert_eq!(payload.status, ReconciliationStatus::Issued);
        assert_eq!(payload.certificate_chain, expected_chain);
        connection.close(0u32.into(), b"issued reconciliation complete");
        endpoint.close(0u32.into(), b"issued reconciliation complete");
    }

    /// Re-submit one durable pending authorization and prove no second leaf is created.
    #[allow(clippy::too_many_arguments)]
    async fn duplicate_pending_submit_test(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
        core_identity: [u8; 32],
        issuance_path: &Path,
        app_id: &str,
        authorization_id: [u8; 16],
    ) {
        let app_key = KeyPair::generate().expect("pending App key");
        let mut csr_params = CertificateParams::new(Vec::<String>::new()).expect("CSR params");
        csr_params
            .distinguished_name
            .push(DnType::CommonName, app_id);
        let csr = csr_params
            .serialize_request(&app_key)
            .expect("CSR")
            .der()
            .to_vec();
        let csr_digest: [u8; 32] = Sha256::digest(&csr).into();
        let uid = crate::material::current_uid().expect("uid");
        let now = current_epoch_seconds().expect("clock");
        let mut store = crate::issuance::PersistentIssuanceResults::open(issuance_path, uid)
            .expect("issuance store");
        store
            .begin_pending(
                crate::issuance::IssuanceResultKey::new(authorization_id, csr_digest)
                    .expect("pending key"),
                app_id,
                1,
                now + 300,
                now,
            )
            .expect("pending seed");
        drop(store);

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("pending client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("pending connect")
            .await
            .expect("pending TLS");
        let (mut send, mut recv) = connection.accept_bi().await.expect("pending stream");
        let challenge_frame = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("pending challenge");
        let challenge: EnrollmentChallengePayload = challenge_frame
            .parse_json(EnrollmentFrameKind::Challenge)
            .expect("pending challenge payload");
        let submission = EnrollmentFrame::json(
            EnrollmentFrameKind::Submit,
            &EnrollmentSubmitPayload {
                app_id: app_id.to_owned(),
                pairing_id: "pending-pairing".to_owned(),
                target_id: "pending-target".to_owned(),
                core_identity,
                authorization_id,
                challenge: challenge.challenge,
                code_proof: [91; 32],
                configuration_generation: 1,
                expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
                csr,
            },
            65_536,
        )
        .expect("pending submission");
        write_enrollment_frame(&mut send, &submission, 65_536)
            .await
            .expect("pending submission write");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_enrollment_frame(&mut recv, 65_536),
        )
        .await;
        assert!(result.is_err() || matches!(result, Ok(Err(_))));
        connection.close(0u32.into(), b"pending duplicate complete");
        endpoint.close(0u32.into(), b"pending duplicate complete");
        let mut store = crate::issuance::PersistentIssuanceResults::open(issuance_path, uid)
            .expect("reopen issuance store");
        let record = store
            .reconcile(
                crate::issuance::IssuanceResultKey::new(authorization_id, csr_digest)
                    .expect("reconcile key"),
                current_epoch_seconds().expect("clock"),
            )
            .expect("reconcile pending")
            .expect("pending record");
        assert_eq!(record.status(), IssuanceResultStatus::Pending);
    }

    /// Enroll one App over the real terminal enrollment ALPN and return its public chain/key.
    async fn enroll_test_app(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
        core_identity: [u8; 32],
        app_id: &str,
        request_id: u8,
    ) -> (Vec<Vec<u8>>, Vec<u8>, [u8; 32]) {
        let app_key = KeyPair::generate().expect("App key");
        let app_key_der = app_key.serialize_der();
        let mut csr_params = CertificateParams::new(Vec::<String>::new()).expect("CSR params");
        csr_params
            .distinguished_name
            .push(DnType::CommonName, app_id);
        let csr = csr_params
            .serialize_request(&app_key)
            .expect("CSR")
            .der()
            .to_vec();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("enrollment connect")
            .await
            .expect("enrollment TLS");
        let (mut send, mut recv) = connection.accept_bi().await.expect("enrollment stream");
        let challenge_frame = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("challenge frame");
        let challenge: EnrollmentChallengePayload = challenge_frame
            .parse_json(EnrollmentFrameKind::Challenge)
            .expect("challenge payload");
        let submission = EnrollmentFrame::json(
            EnrollmentFrameKind::Submit,
            &EnrollmentSubmitPayload {
                app_id: app_id.to_owned(),
                pairing_id: format!("pairing-{request_id}"),
                target_id: format!("target-{request_id}"),
                core_identity,
                authorization_id: [request_id; 16],
                challenge: challenge.challenge,
                code_proof: [request_id.saturating_add(10); 32],
                configuration_generation: 1,
                expires_at_epoch_seconds: challenge.expires_at_epoch_seconds,
                csr,
            },
            65_536,
        )
        .expect("submission frame");
        write_enrollment_frame(&mut send, &submission, 65_536)
            .await
            .expect("submission");
        let issued_frame = match read_enrollment_frame(&mut recv, 65_536).await {
            Ok(frame) => frame,
            Err(error) => {
                let close_reason = connection.closed().await;
                panic!("issued frame failed: {error:?}; close={close_reason:?}");
            }
        };
        assert_eq!(
            issued_frame.kind,
            EnrollmentFrameKind::Issued,
            "enrollment rejected: {:?}",
            issued_frame.kind
        );
        let issued: EnrollmentIssuedPayload = issued_frame
            .parse_json(EnrollmentFrameKind::Issued)
            .expect("issued payload");
        assert_eq!(issued.certificate_chain.len(), 2);
        connection.close(0u32.into(), b"test enrollment complete");
        endpoint.close(0u32.into(), b"test enrollment complete");
        (issued.certificate_chain, app_key_der, issued.fingerprint)
    }

    /// Prove that a normal HDQM frame on the enrollment ALPN is rejected before QRM access.
    async fn enrollment_rejects_normal_qrm_frame(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("enrollment connect")
            .await
            .expect("enrollment TLS");
        let (mut send, mut recv) = connection.accept_bi().await.expect("enrollment stream");
        let challenge = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("challenge");
        assert_eq!(challenge.kind, EnrollmentFrameKind::Challenge);
        let normal_frame = HdqmFrame {
            kind: HdqmKind::DeviceHello,
            request_id: [88; 16],
            payload: Vec::new(),
        }
        .encode()
        .expect("normal frame");
        send.write_all(&normal_frame)
            .await
            .expect("normal frame write");
        let rejection = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("enrollment rejection");
        assert_eq!(rejection.kind, EnrollmentFrameKind::Rejected);
        tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("enrollment terminal close");
        endpoint.close(0u32.into(), b"enrollment protocol boundary");
    }

    /// Hold one authenticated enrollment connection open until the quota test finishes.
    async fn open_enrollment_hold(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
    ) -> (
        quinn::Endpoint,
        quinn::Connection,
        quinn::SendStream,
        quinn::RecvStream,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("enrollment connect")
            .await
            .expect("enrollment TLS");
        let (send, mut recv) = connection.accept_bi().await.expect("enrollment stream");
        let challenge = read_enrollment_frame(&mut recv, 65_536)
            .await
            .expect("quota challenge");
        assert_eq!(challenge.kind, EnrollmentFrameKind::Challenge);
        (endpoint, connection, send, recv)
    }

    /// Prove a revoked certificate cannot re-enter normal QRM after reconnecting.
    async fn assert_revoked_normal_qrm_rejected(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        client_chain: Vec<Vec<u8>>,
        client_key: Vec<u8>,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            client_chain,
            Some(client_key),
            QRM_RELAY_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("revoked reconnect")
            .await
            .expect("revoked TLS transport");
        tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("revoked reconnect must close before QRM use");
        endpoint.close(0u32.into(), b"revoked reconnect");
    }

    /// Prove the separate enrollment connection quota rejects a fifth held handshake.
    async fn assert_enrollment_quota_exhausted(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        core_chain: Vec<Vec<u8>>,
        core_key: Vec<u8>,
    ) {
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                open_enrollment_hold(
                    address,
                    server_certificate.clone(),
                    core_chain.clone(),
                    core_key.clone(),
                )
                .await,
            );
        }
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("quota endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            core_chain,
            Some(core_key),
            QRM_ENROLLMENT_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("quota connect")
            .await
            .expect("quota TLS transport");
        tokio::time::timeout(Duration::from_secs(1), connection.closed())
            .await
            .expect("fifth enrollment connection must close");
        endpoint.close(0u32.into(), b"quota complete");
        for (endpoint, connection, _send, _recv) in held {
            connection.close(0u32.into(), b"quota release");
            endpoint.close(0u32.into(), b"quota release");
        }
    }

    /// Connect one enrolled App to normal QRM and complete the DeviceHello barrier.
    async fn connect_normal_test_app(
        address: SocketAddr,
        server_certificate: Vec<u8>,
        client_chain: Vec<Vec<u8>>,
        client_key: Vec<u8>,
    ) -> (
        quinn::Endpoint,
        quinn::Connection,
        quinn::SendStream,
        quinn::RecvStream,
    ) {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
            .expect("client endpoint");
        endpoint.set_default_client_config(test_client_config(
            server_certificate,
            client_chain,
            Some(client_key),
            QRM_RELAY_ALPN,
        ));
        let connection = endpoint
            .connect(address, "localhost")
            .expect("normal connect")
            .await
            .expect("normal TLS");
        let (mut send, mut recv) = connection.open_bi().await.expect("control stream");
        send_control_frame(
            &mut send,
            HdqmFrame {
                kind: HdqmKind::DeviceHello,
                request_id: [90; 16],
                payload: Vec::new(),
            },
        )
        .await
        .expect("DeviceHello");
        assert_eq!(
            read_control_frame(&mut recv)
                .await
                .expect("DeviceHelloAck")
                .kind,
            HdqmKind::DeviceHelloAck
        );
        (endpoint, connection, send, recv)
    }

    // TEST:relay/src/quic_server.rs[tests::p4_verified_enrollment_and_revocation_isolation]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "superseded by the production HDB1/HDE3 path"]
    async fn p4_verified_enrollment_and_revocation_isolation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temporary root")
            .join(format!("qrm-p4-enrollment-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_identity =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server");
        let core_ca = test_ca("p4-core-enrollment-root");
        let core_intermediate_key = KeyPair::generate().expect("core intermediate key");
        let mut core_intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("core intermediate params");
        core_intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "p4-core-enrollment-intermediate");
        core_intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        core_intermediate_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let core_intermediate_certificate = core_intermediate_params
            .signed_by(&core_intermediate_key, &core_ca)
            .expect("core intermediate");
        let device_ca = test_ca("p4-device-root");
        let (core_certificate, core_key) = test_client_certificate("p4-core", &core_ca);
        let device_key = KeyPair::generate().expect("device intermediate key");
        let mut device_params =
            CertificateParams::new(Vec::<String>::new()).expect("device params");
        device_params
            .distinguished_name
            .push(DnType::CommonName, "p4-device-intermediate");
        device_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        device_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let device_certificate = device_params
            .signed_by(&device_key, &device_ca)
            .expect("device intermediate");

        let server_certificate_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        let trusted_client_ca_path = root.join("device-intermediate.pem");
        let trusted_core_ca_path = root.join("core-enrollment-root.pem");
        let core_intermediate_certificate_path = root.join("core-enrollment-intermediate.pem");
        let core_intermediate_key_path = root.join("core-enrollment-intermediate.key");
        let device_certificate_path = root.join("device-intermediate.pem");
        let device_key_path = root.join("device-intermediate.key");
        let public_root_path = root.join("device-root.pem");
        let allowlist_path = root.join("allowlist.json");
        let issuance_result_path = root.join("issuance.json");
        write_test_material(
            &server_certificate_path,
            server_identity.cert.pem().as_bytes(),
        );
        write_test_material(
            &server_key_path,
            server_identity.signing_key.serialize_pem().as_bytes(),
        );
        write_test_material(&trusted_client_ca_path, device_certificate.pem().as_bytes());
        write_test_material(&trusted_core_ca_path, core_ca.pem().as_bytes());
        write_test_material(
            &core_intermediate_certificate_path,
            core_intermediate_certificate.pem().as_bytes(),
        );
        write_test_material(
            &core_intermediate_key_path,
            core_intermediate_key.serialize_pem().as_bytes(),
        );
        write_test_material(
            &device_certificate_path,
            device_certificate.pem().as_bytes(),
        );
        write_test_material(&device_key_path, device_key.serialize_pem().as_bytes());
        write_test_material(&public_root_path, device_ca.pem().as_bytes());
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\ntrusted_core_enrollment_ca=\"{}\"\ncore_enrollment_intermediate_certificate=\"{}\"\ncore_enrollment_intermediate_private_key=\"{}\"\ndevice_intermediate_certificate=\"{}\"\ndevice_intermediate_private_key=\"{}\"\npublic_root_certificate=\"{}\"\n[enrollment]\nenabled=true\nallowlist_path=\"{}\"\nissuance_result_path=\"{}\"\nmax_handshakes=4\nmax_connections=4\nmax_request_bytes=65536\nmax_csr_bytes=16384\nconnection_lifetime_secs=5\nchallenge_ttl_secs=300\n[limits]\nmax_connections=8\nmax_sessions_per_connection=8\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_certificate_path.display(),
            server_key_path.display(),
            trusted_client_ca_path.display(),
            trusted_core_ca_path.display(),
            core_intermediate_certificate_path.display(),
            core_intermediate_key_path.display(),
            device_certificate_path.display(),
            device_key_path.display(),
            public_root_path.display(),
            allowlist_path.display(),
            issuance_result_path.display(),
        ))
        .expect("verified P4 config");
        // Keep the absolute Unix path short enough for macOS sockaddr_un limits.
        let socket_path = root.join("s");
        let unix_listener = UnixListener::bind(&socket_path).expect("Herdr socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let unix_task = tokio::spawn(async move {
            let (_stream, _) = unix_listener.accept().await.expect("Herdr accept");
            // Keep the accepted upstream stream idle so the test observes Relay-side revocation
            // closing an active bridge rather than a prior Unix EOF ending it.
            std::future::pending::<()>().await;
        });
        let server = QuicRelayServer::bind_with_socket_path(config, 77, socket_path)
            .await
            .expect("bind verified server");
        let address = server.local_addr().expect("server address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = shutdown_rx.await;
        }));
        let server_der = server_identity.cert.der().to_vec();
        let core_chain = vec![core_certificate.der().to_vec(), core_ca.der().to_vec()];
        let core_key_der = core_key.serialize_der();
        let core_identity: [u8; 32] = Sha256::digest(core_certificate.der()).into();
        let (app_a_chain, app_a_key, app_a_fingerprint) = enroll_test_app(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
            core_identity,
            "p4-app-a",
            1,
        )
        .await;
        let (app_b_chain, app_b_key, app_b_fingerprint) = enroll_test_app(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
            core_identity,
            "p4-app-b",
            2,
        )
        .await;
        let core_chain_for_quota = core_chain.clone();
        let core_key_for_quota = core_key_der.clone();
        reconcile_unknown_test(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
        )
        .await;
        let uid = crate::material::current_uid().expect("uid");
        let replay_now = current_epoch_seconds().expect("clock");
        let replay_fingerprint = [61; 32];
        let replay_generation = {
            let allowlist = crate::allowlist::PersistentAllowlist::open(&allowlist_path, uid)
                .expect("replay allowlist");
            allowlist.generation() + 1
        };
        let replay_metadata = crate::enrollment::CertificateMetadata::new(
            crate::enrollment::AppId::new("p4-replay").expect("replay app"),
            crate::enrollment::Fingerprint::from_bytes(replay_fingerprint)
                .expect("replay fingerprint"),
            1,
            replay_generation,
            replay_now,
            replay_now + 3600,
        )
        .expect("replay metadata");
        let mut replay_allowlist =
            crate::allowlist::PersistentAllowlist::open(&allowlist_path, uid)
                .expect("replay allowlist reopen");
        replay_allowlist
            .enroll(replay_metadata)
            .expect("replay allowlist entry");
        drop(replay_allowlist);
        let replay_chain = vec![vec![1, 2], vec![3]];
        let replay_key =
            crate::issuance::IssuanceResultKey::new([51; 16], [52; 32]).expect("replay key");
        let mut replay_store =
            crate::issuance::PersistentIssuanceResults::open(&issuance_result_path, uid)
                .expect("replay issuance store");
        replay_store
            .begin_pending(replay_key, "p4-replay", 1, replay_now + 300, replay_now)
            .expect("replay pending");
        replay_store
            .attach_certificate(
                replay_key,
                replay_chain.clone(),
                replay_fingerprint,
                replay_generation,
                replay_now + 3600,
                replay_now,
            )
            .expect("replay candidate");
        drop(replay_store);
        reconcile_issued_test(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
            [51; 16],
            [52; 32],
            replay_chain.clone(),
        )
        .await;
        // The second query proves the issued result is replayed from durable state.
        reconcile_issued_test(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
            [51; 16],
            [52; 32],
            replay_chain,
        )
        .await;
        duplicate_pending_submit_test(
            address,
            server_der.clone(),
            core_chain.clone(),
            core_key_der.clone(),
            core_identity,
            &issuance_result_path,
            "p4-pending",
            [71; 16],
        )
        .await;
        enrollment_rejects_normal_qrm_frame(address, server_der.clone(), core_chain, core_key_der)
            .await;
        // A certificate chaining only to the Core enrollment CA must not enter normal QRM even
        // though the shared TLS root store accepts that chain at the transport layer.
        let (enrollment_ca_leaf, enrollment_ca_key) =
            test_client_certificate("p4-enrollment-only", &core_ca);
        let mut enrollment_ca_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
                .expect("enrollment-only client endpoint");
        enrollment_ca_endpoint.set_default_client_config(test_client_config(
            server_der.clone(),
            vec![enrollment_ca_leaf.der().to_vec(), core_ca.der().to_vec()],
            Some(enrollment_ca_key.serialize_der()),
            QRM_RELAY_ALPN,
        ));
        let enrollment_ca_result = enrollment_ca_endpoint
            .connect(address, "localhost")
            .expect("enrollment-only connect")
            .await;
        match enrollment_ca_result {
            Err(_) => {}
            Ok(connection) => {
                tokio::time::timeout(Duration::from_secs(1), connection.closed())
                    .await
                    .expect("enrollment CA certificate must close on normal QRM");
            }
        }
        enrollment_ca_endpoint.close(0u32.into(), b"enrollment-only complete");
        let uid = crate::material::current_uid().expect("uid");
        let mut allowlist =
            crate::allowlist::PersistentAllowlist::open(&allowlist_path, uid).expect("allowlist");
        assert_eq!(allowlist.entries().count(), 3);
        assert!(
            allowlist
                .authorize_update(
                    crate::enrollment::Fingerprint::from_bytes(app_a_fingerprint)
                        .expect("A fingerprint")
                )
                .is_ok()
        );
        assert!(
            allowlist
                .authorize_update(
                    crate::enrollment::Fingerprint::from_bytes(app_b_fingerprint)
                        .expect("B fingerprint")
                )
                .is_ok()
        );
        let app_a_chain_for_reconnect = app_a_chain.clone();
        let app_a_key_for_reconnect = app_a_key.clone();
        let (a_endpoint, a_connection, mut a_send, mut a_recv) =
            connect_normal_test_app(address, server_der.clone(), app_a_chain, app_a_key).await;
        let (_a_handle, _a_token, _a_session_send, mut a_session_recv) = open_test_session(
            &a_connection,
            &mut a_send,
            &mut a_recv,
            "default",
            app_a_fingerprint,
            11,
        )
        .await;
        let (b_endpoint, _b_connection, mut b_send, mut b_recv) =
            connect_normal_test_app(address, server_der.clone(), app_b_chain, app_b_key).await;
        // Generation 5 is initial generation 1 plus two App enrollments, one replay entry and one revocation.
        let generation = allowlist
            .revoke(&crate::enrollment::AppId::new("p4-app-a").expect("App A"))
            .expect("revoke App A");
        assert_eq!(generation, 5);
        let reloaded = crate::allowlist::PersistentAllowlist::open(&allowlist_path, uid)
            .expect("reopen allowlist");
        assert!(!reloaded.allows_qrm(
            crate::enrollment::Fingerprint::from_bytes(app_a_fingerprint).expect("A fingerprint")
        ));
        assert!(reloaded.allows_qrm(
            crate::enrollment::Fingerprint::from_bytes(app_b_fingerprint).expect("B fingerprint")
        ));
        assert!(
            reloaded
                .authorize_update(
                    crate::enrollment::Fingerprint::from_bytes(app_b_fingerprint)
                        .expect("B fingerprint")
                )
                .is_ok()
        );
        assert_eq!(
            reloaded.authorize_update(
                crate::enrollment::Fingerprint::from_bytes(app_a_fingerprint)
                    .expect("A fingerprint")
            ),
            Err(crate::enrollment::EnrollmentError::UpdateUnauthorized)
        );
        // Revocation must close an otherwise idle matching connection without requiring a
        // peer-controlled heartbeat or other follow-up control frame.
        let mut session_probe = [0_u8; 1];
        let bridge_result = tokio::time::timeout(
            Duration::from_secs(2),
            a_session_recv.read(&mut session_probe),
        )
        .await
        .expect("revoked active bridge closes");
        assert!(
            matches!(bridge_result, Ok(None) | Ok(Some(0)) | Err(_)),
            "revoked active bridge remained readable: {bridge_result:?}"
        );
        tokio::time::timeout(Duration::from_secs(2), a_connection.closed())
            .await
            .expect("revoked idle connection closes");
        assert_revoked_normal_qrm_rejected(
            address,
            server_der.clone(),
            app_a_chain_for_reconnect,
            app_a_key_for_reconnect,
        )
        .await;
        assert_enrollment_quota_exhausted(
            address,
            server_der.clone(),
            core_chain_for_quota,
            core_key_for_quota,
        )
        .await;
        send_control_frame(
            &mut b_send,
            HdqmFrame {
                kind: HdqmKind::Heartbeat,
                request_id: [92; 16],
                payload: vec![0],
            },
        )
        .await
        .expect("sibling heartbeat");
        assert_eq!(
            read_control_frame(&mut b_recv)
                .await
                .expect("sibling heartbeat ack")
                .kind,
            HdqmKind::Heartbeat
        );
        let mut no_client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
                .expect("no-client endpoint");
        no_client_endpoint.set_default_client_config(test_client_config(
            server_der,
            Vec::new(),
            None,
            QRM_RELAY_ALPN,
        ));
        let no_client_result = no_client_endpoint
            .connect(address, "localhost")
            .expect("no-client connect");
        match no_client_result.await {
            Err(_) => {}
            Ok(connection) => {
                // rustls may finish the transport handshake before the application boundary
                // observes the missing identity; the connection must still close before QRM use.
                tokio::time::timeout(Duration::from_secs(1), connection.closed())
                    .await
                    .expect("missing-client normal QRM must close");
            }
        }
        a_endpoint.close(0u32.into(), b"revoked");
        b_endpoint.close(0u32.into(), b"sibling complete");
        no_client_endpoint.close(0u32.into(), b"no client");
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("server task")
            .expect("server result");
        unix_task.abort();
        let _ = unix_task.await;
        fs::remove_dir_all(root).expect("cleanup");
    }

    // TEST:relay/src/quic_server.rs[tests::server_accepts_only_valid_generation]
    #[test]
    fn server_accepts_only_valid_generation() {
        let server = QuicRelayServer::new(config(), 1).expect("server");
        let debug = format!("{server:?}");
        assert!(!debug.contains("relay_generation: 1"));
        assert_eq!(server.local_addr().unwrap().port(), 18743);
        assert!(server.new_connection(2).is_ok());
        assert!(QuicRelayServer::new(config(), 0).is_err());
    }
}
