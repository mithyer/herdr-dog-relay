//! Production QRM-1 QUIC TLS 1.3 Relay server.
//!
//! The server owns one UDP listener per device, one HDQM control stream per connection and one
//! HDQS stream per approved session. Relay never parses or logs Herdr payload bytes.

use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::BufReader,
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
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};

use crate::{
    allowlist::PersistentAllowlist,
    bridge::{self, BridgeLimits},
    config::{QRM_HANDSHAKE_TIMEOUT_SECS, RelayConfig, SecurityMode},
    enrollment::{
        AppId, CoreAuthorization, CsrDigest, CsrMetadata, EnrollmentChallenge,
        EnrollmentSubmission, Fingerprint, STABLE_LATEST_SELECTOR,
    },
    enrollment_wire::{
        EnrollmentChallengePayload, EnrollmentFrame, EnrollmentFrameKind, EnrollmentIssuedPayload,
        EnrollmentRejectedPayload, EnrollmentSubmitPayload, EnrollmentWireError,
        read_frame as read_enrollment_frame, write_frame as write_enrollment_frame,
    },
    error::{RelayError, RelayResult},
    material::{MAX_PUBLIC_MATERIAL_BYTES, ProtectedFileKind, current_uid, read_protected_file},
    pki::{current_epoch_seconds, issue_certificate},
    quic_wire::{
        DeviceHelloAck, HdqmFrame, HdqmKind, HdqsBinding, HdqsReason, HdqsResponse, SessionOpenAck,
        SessionOpenRequest, SessionPrepareAck, SessionPrepareRequest,
    },
    session_registry::SessionRegistry,
    socket::UnixSocketConnector,
    updater::FixedSourceUpdater,
};

/// ALPN selected by every QRM-1 Relay connection.
pub const QRM_RELAY_ALPN: &[u8] = b"herdr-dog-relay-quic/1";
/// ALPN selected by the terminal App enrollment path.
pub const QRM_ENROLLMENT_ALPN: &[u8] = b"herdr-dog-relay-enroll/1";
/// Maximum retained single-use enrollment authorizations per Relay process.
pub const QRM_MAX_CONSUMED_ENROLLMENT_AUTHORIZATIONS: usize = 4096;
/// Maximum time allowed for the initial control stream and session bind.
pub const QRM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(QRM_HANDSHAKE_TIMEOUT_SECS);

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
    /// Bound Quinn endpoint, absent for the contract-only constructor.
    endpoint: Option<quinn::Endpoint>,
    /// Global connection quota.
    connections: Arc<Semaphore>,
    /// Independent bounded TLS handshakes before ALPN dispatch.
    pre_auth_handshakes: Arc<Semaphore>,
    /// Independent pre-authentication enrollment budget.
    enrollment_handshakes: Arc<Semaphore>,
    /// Independent post-ALPN enrollment connection budget.
    enrollment_connections: Arc<Semaphore>,
    /// In-memory single-use Core authorization IDs invalidated on process restart.
    consumed_enrollment_authorizations: Arc<Mutex<BTreeMap<[u8; 16], u64>>>,
    /// Optional protected App allowlist used by production admission.
    allowlist: Option<Arc<Mutex<PersistentAllowlist>>>,
    /// Optional test-only socket override for deterministic Unix bridge tests.
    socket_override: Option<PathBuf>,
}

impl std::fmt::Debug for QuicRelayServer {
    /// Reports only non-secret listener and generation metadata.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicRelayServer")
            .field("relay_generation_present", &true)
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
        Self::new_inner(config, relay_generation, None, None, None, [1; 32])
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
    #[cfg(test)]
    pub async fn bind_with_socket_path(
        config: RelayConfig,
        relay_generation: u64,
        socket_path: PathBuf,
    ) -> RelayResult<Self> {
        Self::bind_inner(config, relay_generation, Some(socket_path)).await
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
                        let connection = match timeout(owner.handshake_timeout(), incoming).await {
                            Ok(Ok(connection)) => connection,
                            _ => return,
                        };
                        drop(handshake_permit);
                        let is_enrollment = negotiated_alpn(&connection)
                            .map(|protocol| protocol == QRM_ENROLLMENT_ALPN)
                            .unwrap_or(false);
                        let connection_permit = if is_enrollment {
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
        let address = config.listener().socket_addr()?;
        let server_config = build_server_config(&config)?;
        let endpoint = quinn::Endpoint::server(server_config, address)
            .map_err(|error| RelayError::io("binding QRM UDP listener", error))?;
        let relay_identity = load_relay_identity(&config)?;
        let allowlist = if config.enrollment().enabled() {
            let uid = current_uid()?;
            Some(Arc::new(Mutex::new(PersistentAllowlist::open(
                config.enrollment().allowlist_path(),
                uid,
            )?)))
        } else {
            None
        };
        Self::new_inner(
            config,
            relay_generation,
            Some(endpoint),
            socket_override,
            allowlist,
            relay_identity,
        )
    }

    /// Constructs the owner after common validation.
    fn new_inner(
        config: RelayConfig,
        relay_generation: u64,
        endpoint: Option<quinn::Endpoint>,
        socket_override: Option<PathBuf>,
        allowlist: Option<Arc<Mutex<PersistentAllowlist>>>,
        relay_identity: [u8; 32],
    ) -> RelayResult<Self> {
        if relay_generation == 0 {
            return Err(RelayError::ListenerStartup {
                reason: "Relay generation must be non-zero",
            });
        }
        config.validate()?;
        Ok(Self {
            connections: Arc::new(Semaphore::new(config.limits().max_connections())),
            pre_auth_handshakes: Arc::new(Semaphore::new(
                config
                    .limits()
                    .max_connections()
                    .saturating_add(config.enrollment().max_handshakes()),
            )),
            enrollment_handshakes: Arc::new(Semaphore::new(config.enrollment().max_handshakes())),
            enrollment_connections: Arc::new(Semaphore::new(config.enrollment().max_connections())),
            config,
            relay_generation,
            relay_identity,
            endpoint,
            consumed_enrollment_authorizations: Arc::new(Mutex::new(BTreeMap::new())),
            allowlist,
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
                .serve_enrollment_connection(
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
        if let (Some(allowlist), Some(fingerprint)) = (&self.allowlist, peer_fingerprint)
            && !allowlist.lock().await.allows_qrm(fingerprint)
        {
            return Err(RelayError::QuicAuthentication);
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
        loop {
            tokio::select! {
                _ = expiry_tick.tick() => {
                    let expired = registry.lock().await.reap_expired_handles(Instant::now());
                    for handle in expired {
                        self.cancel_session(&session_controls, handle).await;
                    }
                }
                joined = session_tasks.join_next(), if !session_tasks.is_empty() => {
                    let _ = joined;
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
                session = connection.accept_bi() => {
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
    ) -> RelayResult<bool> {
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

    /// Handles one authenticated, terminal enrollment connection before any QRM frame is accepted.
    async fn serve_enrollment_connection(
        &self,
        connection: quinn::Connection,
        core_identity: Fingerprint,
    ) -> RelayResult<()> {
        let _handshake_permit =
            try_acquire(&self.enrollment_handshakes).ok_or(RelayError::ResourceLimit)?;
        let _connection_permit =
            try_acquire(&self.enrollment_connections).ok_or(RelayError::ResourceLimit)?;
        let (mut send, mut recv) = timeout(self.handshake_timeout(), connection.accept_bi())
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
        let frame = match timeout(
            Duration::from_secs(self.config.enrollment().connection_lifetime_secs()),
            read_enrollment_frame(&mut recv, self.config.enrollment().max_request_bytes()),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => return self.reject_enrollment(&mut send, error).await,
            Err(_) => {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::ResourceLimit)
                    .await;
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
        if EnrollmentSubmission::new(authorization, csr).is_err() {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                .await;
        }
        let Some(allowlist) = &self.allowlist else {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::PersistenceFailed)
                .await;
        };
        {
            let mut consumed = self.consumed_enrollment_authorizations.lock().await;
            consumed.retain(|_, expiry| *expiry >= submission_now);
            if consumed.len() >= QRM_MAX_CONSUMED_ENROLLMENT_AUTHORIZATIONS {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::ResourceLimit)
                    .await;
            }
            if consumed
                .insert(
                    submission.authorization_id,
                    submission.expires_at_epoch_seconds,
                )
                .is_some()
            {
                return self
                    .reject_enrollment(&mut send, EnrollmentWireError::AuthorizationRejected)
                    .await;
            }
        }
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
        let metadata = match issued.metadata(app_id, next_generation) {
            Ok(metadata) => metadata,
            Err(error) => return self.reject_enrollment(&mut send, error.into()).await,
        };
        let fingerprint = metadata.fingerprint().to_bytes();
        let not_after = metadata.not_after_epoch_seconds();
        if allowlist.lock().await.enroll(metadata).is_err() {
            return self
                .reject_enrollment(&mut send, EnrollmentWireError::PersistenceFailed)
                .await;
        }
        let response = EnrollmentFrame::json(
            EnrollmentFrameKind::Issued,
            &EnrollmentIssuedPayload {
                certificate_chain: issued.certificate_chain(),
                fingerprint,
                allowlist_generation: next_generation,
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
        connection.close(0u32.into(), b"enrollment complete");
        Ok(())
    }

    /// Sends one sanitized terminal enrollment rejection and closes the stream.
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

    /// Clones only immutable server state for a spawned connection task.
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            relay_generation: self.relay_generation,
            relay_identity: self.relay_identity,
            endpoint: None,
            connections: Arc::clone(&self.connections),
            pre_auth_handshakes: Arc::clone(&self.pre_auth_handshakes),
            enrollment_handshakes: Arc::clone(&self.enrollment_handshakes),
            enrollment_connections: Arc::clone(&self.enrollment_connections),
            consumed_enrollment_authorizations: Arc::clone(
                &self.consumed_enrollment_authorizations,
            ),
            allowlist: self.allowlist.clone(),
            socket_override: self.socket_override.clone(),
        }
    }
}

/// Performs one fixed-source update without invoking a shell or accepting peer arguments.
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
    let installed = std::env::current_exe().map_err(|_| RelayError::Update {
        operation: "running stable-latest update",
        reason: "current executable path is unavailable",
    })?;
    let backup = installed.with_extension("previous");
    updater.replace_binary(&staged, &installed, &backup)
}

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
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|_| RelayError::TlsConfiguration {
                    reason: "client CA verifier construction failed",
                })?;
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
        vec![QRM_RELAY_ALPN.to_vec(), QRM_ENROLLMENT_ALPN.to_vec()]
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

/// Loads all PEM certificates from a bounded deployment path.
fn load_certificates(path: &Path) -> RelayResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path).map_err(|_| RelayError::TlsConfiguration {
        reason: "certificate file could not be opened",
    })?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RelayError::TlsConfiguration {
            reason: "certificate PEM is invalid",
        })
}

/// Loads one PEM private key without retaining its source path in diagnostics.
fn load_private_key(path: &Path) -> RelayResult<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|_| RelayError::TlsConfiguration {
        reason: "private-key file could not be opened",
    })?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
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
    use crate::quic_wire::{
        HdqmFrame, HdqmKind, HdqsBinding, HdqsResponse, SessionName, SessionOpenAck,
        SessionOpenRequest, SessionPrepareAck, SessionPrepareRequest,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
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

    // TEST:relay/src/quic_server.rs[tests::qrm_quic_three_session_network_isolated]
    #[tokio::test(flavor = "current_thread")]
    async fn qrm_quic_three_session_network_isolated() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temp root")
            .join(format!("qrm-three-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
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
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"development_unverified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(), server_key_path.display(), server_cert_path.display()
        )).expect("config");
        let server = QuicRelayServer::bind_with_socket_path(config, 11, socket_path)
            .await
            .expect("bind server");
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
        read_control_frame(&mut control_recv)
            .await
            .expect("hello ack");
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
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
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
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
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
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
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
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
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
        let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let root = temp_root.join(format!("qrm-quic-{}-{nonce}", std::process::id()));
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
        fs::write(&server_cert_path, server_cert.cert.pem()).expect("server cert file");
        fs::write(&server_key_path, server_cert.signing_key.serialize_pem())
            .expect("server key file");
        fs::write(&client_cert_path, client_cert.cert.pem()).expect("client cert file");
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
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={test_port}\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(), server_key_path.display(), client_cert_path.display()
        )).expect("config");
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
        let client_ca =
            rcgen::generate_simple_self_signed(vec!["client-ca".to_owned()]).expect("client CA");
        let server_cert_path = root.join("server.pem");
        let server_key_path = root.join("server.key");
        let client_ca_path = root.join("client-ca.pem");
        fs::write(&server_cert_path, server.cert.pem()).expect("server cert");
        fs::write(&server_key_path, server.signing_key.serialize_pem()).expect("server key");
        fs::write(&client_ca_path, client_ca.cert.pem()).expect("client ca");
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("free UDP port")
            .local_addr()
            .expect("UDP address")
            .port();
        let config = RelayConfig::from_toml_str(&format!(
            "[listener]\nlisten_address=\"127.0.0.1\"\nport={port}\n[security]\nmode=\"verified\"\nserver_certificate=\"{}\"\nserver_private_key=\"{}\"\ntrusted_client_ca=\"{}\"\n[limits]\nmax_connections=64\nmax_sessions_per_connection=64\nmax_control_frame_bytes=65536\nbuffer_bytes=65536\nhandshake_timeout_secs=5\nidle_timeout_secs=900\n",
            server_cert_path.display(), server_key_path.display(), client_ca_path.display()
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
