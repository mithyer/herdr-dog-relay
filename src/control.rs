//! RSB-3 Broker Control listener and session-bound data bridge.
//!
//! This module connects the RSB-2 Manager lifecycle to the frozen RSB-1 HDBR/HDBD boundary. It
//! accepts only bounded Broker control frames, keeps lease authority in memory, validates HDBD
//! before forwarding, and reuses the existing protocol-agnostic byte bridge for Herdr bytes.

use crate::{
    bridge::{self, BridgeLimits},
    broker::{
        BROKER_CONTROL_MAGIC, BROKER_DATA_MAGIC, BROKER_DATA_PORT_BASE, BROKER_DATA_PORT_LAST,
        BROKER_DISCOVERY_PORT_BASE, BROKER_DISCOVERY_PORT_LAST, BROKER_FRAME_HEADER_BYTES,
        BROKER_MAX_FRAME_BYTES, BrokerBindingDecision, BrokerBindingExpectation,
        BrokerBindingRequest, BrokerBindingResponse, BrokerControlKind, BrokerFrame,
    },
    config::ListenerClass,
    error::{RelayError, RelayResult},
    handshake::server_handshake,
    manager::{LeaseToken, Manager, SessionName},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, oneshot},
    task::JoinHandle,
    time::timeout,
};

/// The bounded deadline for one Broker control frame exchange.
pub const BROKER_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

const BROKER_CAPABILITY_ENSURE: u32 = 1 << 0;
const BROKER_CAPABILITY_HEARTBEAT: u32 = 1 << 1;
const BROKER_CAPABILITY_RELEASE: u32 = 1 << 2;
const BROKER_CAPABILITY_STATUS: u32 = 1 << 3;
const BROKER_KNOWN_CAPABILITIES: u32 = BROKER_CAPABILITY_ENSURE
    | BROKER_CAPABILITY_HEARTBEAT
    | BROKER_CAPABILITY_RELEASE
    | BROKER_CAPABILITY_STATUS;

/// A bounded Broker control listener backed by one Manager instance.
pub struct BrokerControlServer {
    /// The fixed-range control listener.
    listener: TcpListener,
    /// Shared Manager and authority state used by control/data tasks.
    state: Arc<Mutex<BrokerServiceState>>,
}

impl std::fmt::Debug for BrokerControlServer {
    /// Render listener and bounded state metadata without exposing authority values.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerControlServer")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("state_present", &true)
            .finish()
    }
}

impl BrokerControlServer {
    /// Bind a local Broker listener with a generated opaque Broker instance identity.
    ///
    /// # Arguments
    ///
    /// * `manager` - The Manager owning session, lease and child lifecycle state.
    /// * `address` - A configured address whose port is within `18743..18752`.
    ///
    /// # Returns
    ///
    /// A bounded control server or a redacted policy/bind error.
    pub async fn bind(manager: Manager, address: SocketAddr) -> RelayResult<Self> {
        Self::bind_with_instance_id(manager, address, rand::random()).await
    }

    /// Bind a Broker listener with deterministic identity for contract tests.
    ///
    /// # Arguments
    ///
    /// * `manager` - The Manager owning session, lease and child lifecycle state.
    /// * `address` - A configured address whose port is within `18743..18752`.
    /// * `broker_instance_id` - Opaque process identity retained only in memory.
    ///
    /// # Returns
    ///
    /// A bounded control server or a redacted policy/bind error.
    // TEST:relay/tests/rsb3_control.rs[broker_listener_exposes_bounded_discovery]
    pub async fn bind_with_instance_id(
        manager: Manager,
        address: SocketAddr,
        broker_instance_id: [u8; 16],
    ) -> RelayResult<Self> {
        if !(BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST).contains(&address.port()) {
            return Err(RelayError::InvalidConfiguration {
                field: "broker_control_port",
                reason: "must remain in 18743..18752",
            });
        }
        let listener = TcpListener::bind(address)
            .await
            .map_err(|_| RelayError::ListenerAddressUnavailable)?;
        Self::from_listener(manager, listener, broker_instance_id)
    }

    /// Bind the first available fixed-range control port, trying Manager's preferred port first.
    ///
    /// # Arguments
    ///
    /// * `manager` - The Manager owning session, lease and child lifecycle state.
    /// * `bind_ip` - Explicit local/listener address selected by deployment policy.
    ///
    /// # Returns
    ///
    /// A control server on `18743..18752`, or a bounded port exhaustion error.
    pub async fn bind_preferred(manager: Manager, bind_ip: IpAddr) -> RelayResult<Self> {
        let preferred = manager.config().preferred_broker_port();
        let mut candidates = Vec::with_capacity(10);
        candidates.push(preferred);
        candidates.extend(
            (BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST)
                .filter(|port| *port != preferred),
        );
        let broker_instance_id: [u8; 16] = rand::random();
        for port in candidates {
            if let Ok(listener) = TcpListener::bind(SocketAddr::new(bind_ip, port)).await {
                return Self::from_listener(manager, listener, broker_instance_id);
            }
        }
        Err(RelayError::PortRangeExhausted)
    }

    /// Build shared service state after a bounded listener has been selected.
    fn from_listener(
        manager: Manager,
        listener: TcpListener,
        broker_instance_id: [u8; 16],
    ) -> RelayResult<Self> {
        let local_addr = listener
            .local_addr()
            .map_err(|_| RelayError::ListenerAddressUnavailable)?;
        if !(BROKER_DISCOVERY_PORT_BASE..=BROKER_DISCOVERY_PORT_LAST).contains(&local_addr.port()) {
            return Err(RelayError::InvalidConfiguration {
                field: "broker_control_port",
                reason: "must remain in 18743..18752",
            });
        }
        let state = Arc::new(Mutex::new(BrokerServiceState {
            manager,
            broker_instance_id,
            control_port: local_addr.port(),
            authorities: BTreeMap::new(),
            data_ports: BTreeSet::new(),
            data_shutdown: BTreeMap::new(),
            data_tasks: BTreeMap::new(),
        }));
        Ok(Self { listener, state })
    }

    /// Serve Broker control/data connections until the supplied shutdown future completes.
    ///
    /// # Arguments
    ///
    /// * `self` - Shared server owner whose Manager remains alive for the loop.
    /// * `shutdown` - Future completing on SIGINT/SIGTERM or a test cancellation.
    ///
    /// # Returns
    ///
    /// `Ok(())` after shutdown, or a bounded control/reap error.
    pub async fn serve_until<F>(self: Arc<Self>, shutdown: F) -> RelayResult<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let reap_interval_secs = self
            .state
            .lock()
            .await
            .manager
            .config()
            .heartbeat_interval()
            .as_secs();
        let mut reap_interval =
            tokio::time::interval(Duration::from_secs(reap_interval_secs.max(1)));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = self.serve_one() => result?,
                _ = reap_interval.tick() => {
                    let now = crate::manager::epoch_seconds()?;
                    Self::reap_state(&self.state, now).await?;
                }
            }
        }
    }

    /// Reap Manager leases, authority records and data listeners as one bounded lifecycle step.
    async fn reap_state(state: &Arc<Mutex<BrokerServiceState>>, now: u64) -> RelayResult<()> {
        let handles = {
            let mut guard = state.lock().await;
            guard.manager.reap(now).await?;
            let stale_authorities: Vec<[u8; 32]> = guard
                .authorities
                .keys()
                .copied()
                .filter(|token| {
                    !guard
                        .manager
                        .lease_is_active(LeaseToken::from_bytes(*token), now)
                })
                .collect();
            for token in stale_authorities {
                guard.authorities.remove(&token);
            }
            let active_ports: BTreeSet<u16> = guard
                .manager
                .status()
                .into_iter()
                .map(|status| status.data_port)
                .collect();
            let stale_ports: Vec<u16> = guard
                .data_ports
                .iter()
                .copied()
                .filter(|port| !active_ports.contains(port))
                .collect();
            let mut handles = Vec::new();
            for port in stale_ports {
                guard.data_ports.remove(&port);
                if let Some(shutdown) = guard.data_shutdown.remove(&port) {
                    let _ = shutdown.send(());
                }
                if let Some(handle) = guard.data_tasks.remove(&port) {
                    handles.push(handle);
                }
            }
            handles
        };
        for handle in handles {
            let _ = handle.await;
        }
        Ok(())
    }

    /// Reap expired leases and idle data listeners using an explicit test/owner clock.
    ///
    /// # Arguments
    ///
    /// * `now` - Epoch seconds used by Manager lease and idle-grace policy.
    ///
    /// # Returns
    ///
    /// `Ok(())` after authority/listener cleanup or a redacted lifecycle error.
    // TEST:relay/tests/rsb3_control.rs[broker_expired_authority_and_data_listener_are_reaped]
    pub async fn reap_once(&self, now: u64) -> RelayResult<()> {
        Self::reap_state(&self.state, now).await
    }

    /// Return the selected Broker control address.
    ///
    /// # Returns
    ///
    /// The non-secret local listener address.
    pub fn local_addr(&self) -> RelayResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|_| RelayError::ListenerAddressUnavailable)
    }

    /// Accept and process one bounded Broker control connection.
    ///
    /// # Returns
    ///
    /// `Ok(())` after one connection closes, or a stable listener/control error.
    // TEST:relay/tests/rsb3_control.rs[broker_control_round_trip_and_hdbd_gate]
    pub async fn serve_one(&self) -> RelayResult<()> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| RelayError::ListenerAddressUnavailable)?;
        let _ = handle_control_connection(stream, self.state.clone()).await;
        Ok(())
    }
}

/// Manager and authority state shared by the control and data listeners.
struct BrokerServiceState {
    /// Manager-owned session and lease lifecycle.
    manager: Manager,
    /// Opaque Broker process identity.
    broker_instance_id: [u8; 16],
    /// Fixed control port returned during discovery.
    control_port: u16,
    /// Active authority records indexed by opaque lease token.
    authorities: BTreeMap<[u8; 32], AuthorityRecord>,
    /// Data listeners already spawned for Manager-reserved ports.
    data_ports: BTreeSet<u16>,
    /// Shutdown channels for active per-port listeners.
    data_shutdown: BTreeMap<u16, oneshot::Sender<()>>,
    /// Join handles used to await listener teardown before port reuse.
    data_tasks: BTreeMap<u16, JoinHandle<()>>,
}

/// The control-plane authority tuple retained for one lease.
#[derive(Clone)]
struct AuthorityRecord {
    /// Core process identity.
    core_instance_id: [u8; 16],
    /// Broker process identity.
    broker_instance_id: [u8; 16],
    /// Broker restart generation.
    broker_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Session fingerprint.
    session_fingerprint: [u8; 32],
    /// Opaque lease token used as the map key.
    lease_token: [u8; 32],
    /// Canonical session name.
    session: String,
}

/// Parsed HDBR authority payload shared by heartbeat and release handlers.
struct ControlAuthority {
    /// Request correlation identifier.
    request_id: [u8; 16],
    /// Core process identity.
    core_instance_id: [u8; 16],
    /// Broker process identity.
    broker_instance_id: [u8; 16],
    /// Broker generation.
    broker_generation: u64,
    /// Session configuration generation.
    configuration_generation: u64,
    /// Session fingerprint.
    session_fingerprint: [u8; 32],
    /// Opaque lease token.
    lease_token: [u8; 32],
    /// Canonical session name.
    session: SessionName,
}

/// Handle one request and close the control connection after its correlated response.
async fn handle_control_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<BrokerServiceState>>,
) -> RelayResult<()> {
    let frame = read_frame(&mut stream, BROKER_CONTROL_MAGIC).await?;
    let response = match frame.control_kind().map_err(protocol_error)? {
        BrokerControlKind::DiscoveryRequest => handle_discovery(&state, &frame).await?,
        BrokerControlKind::EnsureRequest => handle_ensure(&state, &frame).await?,
        BrokerControlKind::HeartbeatRequest => handle_heartbeat(&state, &frame).await?,
        BrokerControlKind::ReleaseRequest => handle_release(&state, &frame).await?,
        BrokerControlKind::StatusRequest => handle_status(&state, &frame).await?,
        _ => {
            return Err(RelayError::Manager {
                reason: "Broker response kind was sent as a request",
            });
        }
    };
    write_frame(&mut stream, &response).await
}

/// Encode the fixed discovery response without exposing Manager state or secrets.
async fn handle_discovery(
    state: &Arc<Mutex<BrokerServiceState>>,
    frame: &BrokerFrame,
) -> RelayResult<Vec<u8>> {
    if !frame.payload().is_empty() {
        return Err(RelayError::Manager {
            reason: "Broker discovery payload is invalid",
        });
    }
    let guard = state.lock().await;
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(&guard.broker_instance_id);
    payload.extend_from_slice(&guard.manager.broker_generation().to_be_bytes());
    payload.extend_from_slice(&guard.control_port.to_be_bytes());
    payload.extend_from_slice(&BROKER_DATA_PORT_BASE.to_be_bytes());
    payload.extend_from_slice(&BROKER_DATA_PORT_LAST.to_be_bytes());
    payload.extend_from_slice(&BROKER_KNOWN_CAPABILITIES.to_be_bytes());
    encode_control(BrokerControlKind::DiscoveryResponse, payload)
}

/// Ensure one Manager lease and publish a matching authority/data listener.
async fn handle_ensure(
    state: &Arc<Mutex<BrokerServiceState>>,
    frame: &BrokerFrame,
) -> RelayResult<Vec<u8>> {
    let request = parse_ensure(frame)?;
    let now = crate::manager::epoch_seconds()?;
    let mut guard = state.lock().await;
    let grant = match guard.manager.ensure(request.session.as_str(), now).await {
        Ok(grant) => grant,
        Err(error) => return encode_ensure_rejection(request.request_id, error),
    };
    let token = *grant.token().as_bytes();
    let data_port = grant.data_port();
    if !guard.data_ports.contains(&data_port) {
        let listener = match TcpListener::bind(("127.0.0.1", data_port)).await {
            Ok(listener) => listener,
            Err(_) => {
                let _ = guard.manager.release(grant.token(), now);
                return encode_ensure_rejection(
                    request.request_id,
                    RelayError::ListenerAddressUnavailable,
                );
            }
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let weak_state = Arc::downgrade(state);
        let handle = tokio::spawn(async move {
            run_data_listener(listener, weak_state, shutdown_rx).await;
        });
        guard.data_ports.insert(data_port);
        guard.data_shutdown.insert(data_port, shutdown_tx);
        guard.data_tasks.insert(data_port, handle);
    }
    let authority = AuthorityRecord {
        core_instance_id: request.core_instance_id,
        broker_instance_id: guard.broker_instance_id,
        broker_generation: grant.broker_generation(),
        configuration_generation: grant.configuration_generation(),
        session_fingerprint: *grant.fingerprint().as_bytes(),
        lease_token: token,
        session: request.session.as_str().to_owned(),
    };
    guard.authorities.insert(token, authority);
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(&request.request_id);
    payload.push(0);
    payload.extend_from_slice(&guard.broker_instance_id);
    payload.extend_from_slice(&grant.broker_generation().to_be_bytes());
    payload.extend_from_slice(grant.fingerprint().as_bytes());
    payload.extend_from_slice(&data_port.to_be_bytes());
    payload.extend_from_slice(&grant.configuration_generation().to_be_bytes());
    payload.extend_from_slice(grant.token().as_bytes());
    payload
        .extend_from_slice(&(guard.manager.config().lease_expiry().as_secs() as u32).to_be_bytes());
    encode_control(BrokerControlKind::EnsureResponse, payload)
}

/// Return an opaque bounded ensure rejection without leaking Manager diagnostics.
fn encode_ensure_rejection(request_id: [u8; 16], error: RelayError) -> RelayResult<Vec<u8>> {
    let code = match error {
        RelayError::UpstreamUnavailable | RelayError::SocketIdentity { .. } => 2,
        RelayError::PortRangeExhausted => 3,
        RelayError::Manager { .. }
        | RelayError::ChildLifecycle { .. }
        | RelayError::InvalidConfiguration { .. }
        | RelayError::InvalidFingerprint
        | RelayError::InvalidLease
        | RelayError::ListenerAddressUnavailable
        | RelayError::Io { .. }
        | RelayError::ConfigurationRead
        | RelayError::ConfigurationSyntax => 4,
        _ => 4,
    };
    encode_control(
        BrokerControlKind::EnsureResponse,
        [request_id.as_slice(), &[code]].concat(),
    )
}

/// Renew one lease only when the complete authority tuple still matches.
async fn handle_heartbeat(
    state: &Arc<Mutex<BrokerServiceState>>,
    frame: &BrokerFrame,
) -> RelayResult<Vec<u8>> {
    let request = parse_authority(frame, BrokerControlKind::HeartbeatRequest)?;
    let mut guard = state.lock().await;
    let accepted = guard
        .authorities
        .get(&request.lease_token)
        .is_some_and(|expected| authority_matches(expected, &request));
    let result = if accepted {
        let token = LeaseToken::from_bytes(request.lease_token);
        match guard
            .manager
            .heartbeat(token, crate::manager::epoch_seconds()?)
        {
            Ok(grant) => {
                if let Some(authority) = guard.authorities.get_mut(&request.lease_token) {
                    authority.configuration_generation = grant.configuration_generation();
                    authority.broker_generation = grant.broker_generation();
                }
                (0_u8, guard.manager.config().lease_expiry().as_secs() as u32)
            }
            Err(_) => (1_u8, 0_u32),
        }
    } else {
        (1_u8, 0_u32)
    };
    let mut payload = Vec::with_capacity(21);
    payload.extend_from_slice(&request.request_id);
    payload.push(result.0);
    if result.0 == 0 {
        payload.extend_from_slice(&result.1.to_be_bytes());
    }
    encode_control(BrokerControlKind::HeartbeatResponse, payload)
}

/// Release one lease and remove only its authority record.
async fn handle_release(
    state: &Arc<Mutex<BrokerServiceState>>,
    frame: &BrokerFrame,
) -> RelayResult<Vec<u8>> {
    let request = parse_authority(frame, BrokerControlKind::ReleaseRequest)?;
    let mut guard = state.lock().await;
    let result = if let Some(expected) = guard.authorities.get(&request.lease_token) {
        if !authority_matches(expected, &request) {
            2_u8
        } else {
            let token = LeaseToken::from_bytes(request.lease_token);
            match guard
                .manager
                .release(token, crate::manager::epoch_seconds()?)
            {
                Ok(()) => {
                    guard.authorities.remove(&request.lease_token);
                    0_u8
                }
                Err(_) => 2_u8,
            }
        }
    } else {
        1_u8
    };
    encode_control(
        BrokerControlKind::ReleaseResponse,
        [request.request_id.as_slice(), &[result]].concat(),
    )
}

/// Return sanitized status for one normalized session.
async fn handle_status(
    state: &Arc<Mutex<BrokerServiceState>>,
    frame: &BrokerFrame,
) -> RelayResult<Vec<u8>> {
    let request = parse_status(frame)?;
    let guard = state.lock().await;
    let status = guard
        .manager
        .status()
        .into_iter()
        .find(|status| status.session.as_str() == request.session.as_str());
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&request.request_id);
    let Some(status) = status else {
        payload.push(0);
        return encode_control(BrokerControlKind::StatusResponse, payload);
    };
    if status.active_leases == 0 {
        payload.push(3);
    } else {
        payload.push(4);
    }
    payload.extend_from_slice(status.fingerprint.as_bytes());
    payload.extend_from_slice(&status.configuration_generation.to_be_bytes());
    payload.extend_from_slice(&status.data_port.to_be_bytes());
    payload.extend_from_slice(&(status.active_leases as u16).to_be_bytes());
    encode_control(BrokerControlKind::StatusResponse, payload)
}

/// Accept HDBD after HDRL and bridge only a validated lease to the Manager socket.
async fn run_data_listener(
    listener: TcpListener,
    weak_state: Weak<Mutex<BrokerServiceState>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let connection_state = weak_state.clone();
                tokio::spawn(async move {
                    let _ = handle_data_connection(stream, connection_state).await;
                });
            }
        }
    }
}

/// Validate one data connection and hand opaque bytes to the existing bridge.
async fn handle_data_connection(
    mut stream: TcpStream,
    weak_state: Weak<Mutex<BrokerServiceState>>,
) -> RelayResult<()> {
    timeout(
        BROKER_CONTROL_TIMEOUT,
        server_handshake(&mut stream, ListenerClass::Tailscale),
    )
    .await
    .map_err(|_| RelayError::RelayHandshakeTimeout)??;
    let frame = read_frame(&mut stream, BROKER_DATA_MAGIC).await?;
    let request = BrokerBindingRequest::decode(&frame).map_err(protocol_error)?;
    let state = weak_state.upgrade().ok_or(RelayError::InvalidLease)?;
    let (response, unix_stream): (BrokerBindingResponse, Option<tokio::net::UnixStream>) = {
        let guard = state.lock().await;
        let (mut response, authority) = match guard.authorities.get(&request.lease_token()).cloned()
        {
            Some(authority) => {
                let expected = BrokerBindingExpectation::new(
                    authority.core_instance_id,
                    authority.broker_instance_id,
                    authority.broker_generation,
                    authority.configuration_generation,
                    authority.session_fingerprint,
                    authority.lease_token,
                    &authority.session,
                )
                .map_err(protocol_error)?;
                let decision = request.compare(&expected);
                (
                    BrokerBindingResponse {
                        decision: binding_status(decision),
                        broker_generation: authority.broker_generation,
                        configuration_generation: authority.configuration_generation,
                    },
                    Some((authority, decision)),
                )
            }
            None => (
                BrokerBindingResponse {
                    decision: BrokerBindingDecision::LeaseRejected,
                    broker_generation: guard.manager.broker_generation(),
                    configuration_generation: 0,
                },
                None,
            ),
        };
        if let Some((_authority, BrokerBindingDecision::Accepted)) = authority {
            let session = SessionName::normalize(request.session())?;
            let unix = guard
                .manager
                .open_bound_stream(
                    LeaseToken::from_bytes(request.lease_token()),
                    &session,
                    crate::manager::epoch_seconds()?,
                )
                .await;
            match unix {
                Ok(unix) => (response, Some(unix)),
                Err(_) => {
                    response.decision = BrokerBindingDecision::LeaseRejected;
                    (response, None)
                }
            }
        } else {
            (response, None)
        }
    };
    write_frame(&mut stream, &response.encode().map_err(protocol_error)?).await?;
    if response.decision != BrokerBindingDecision::Accepted {
        return Ok(());
    }
    let Some(unix_stream) = unix_stream else {
        return Ok(());
    };
    let _ = bridge::run(stream, unix_stream, BridgeLimits::v1()).await;
    Ok(())
}

/// Convert the Relay-side binding decision into the frozen HDBD response status.
fn binding_status(decision: BrokerBindingDecision) -> BrokerBindingDecision {
    decision
}

/// Parse an ensure request without duplicating the public Core wire model.
fn parse_ensure(frame: &BrokerFrame) -> RelayResult<EnsureRequest> {
    if frame.control_kind().map_err(protocol_error)? != BrokerControlKind::EnsureRequest {
        return Err(RelayError::Manager {
            reason: "Broker request kind is invalid",
        });
    }
    let payload = frame.payload();
    let mut cursor = 0;
    let request_id = take_array::<16>(payload, &mut cursor)?;
    let core_instance_id = take_array::<16>(payload, &mut cursor)?;
    let session = take_session(payload, &mut cursor)?;
    finish_payload(payload, cursor)?;
    Ok(EnsureRequest {
        request_id,
        core_instance_id,
        session,
    })
}

/// Parse a heartbeat or release authority request.
fn parse_authority(
    frame: &BrokerFrame,
    expected: BrokerControlKind,
) -> RelayResult<ControlAuthority> {
    if frame.control_kind().map_err(protocol_error)? != expected {
        return Err(RelayError::Manager {
            reason: "Broker authority request kind is invalid",
        });
    }
    let payload = frame.payload();
    let mut cursor = 0;
    let request_id = take_array::<16>(payload, &mut cursor)?;
    let core_instance_id = take_array::<16>(payload, &mut cursor)?;
    let broker_instance_id = take_array::<16>(payload, &mut cursor)?;
    let broker_generation = take_u64(payload, &mut cursor)?;
    let configuration_generation = take_u64(payload, &mut cursor)?;
    let session_fingerprint = take_array::<32>(payload, &mut cursor)?;
    let lease_token = take_array::<32>(payload, &mut cursor)?;
    let session = take_session(payload, &mut cursor)?;
    finish_payload(payload, cursor)?;
    Ok(ControlAuthority {
        request_id,
        core_instance_id,
        broker_instance_id,
        broker_generation,
        configuration_generation,
        session_fingerprint,
        lease_token,
        session,
    })
}

/// Parse a status request for one normalized session.
fn parse_status(frame: &BrokerFrame) -> RelayResult<StatusRequest> {
    if frame.control_kind().map_err(protocol_error)? != BrokerControlKind::StatusRequest {
        return Err(RelayError::Manager {
            reason: "Broker status request kind is invalid",
        });
    }
    let payload = frame.payload();
    let mut cursor = 0;
    let request_id = take_array::<16>(payload, &mut cursor)?;
    let _core_instance_id = take_array::<16>(payload, &mut cursor)?;
    let session = take_session(payload, &mut cursor)?;
    finish_payload(payload, cursor)?;
    Ok(StatusRequest {
        request_id,
        session,
    })
}

/// Compare every authority component in the frozen order.
fn authority_matches(expected: &AuthorityRecord, actual: &ControlAuthority) -> bool {
    expected.core_instance_id == actual.core_instance_id
        && expected.broker_instance_id == actual.broker_instance_id
        && expected.broker_generation == actual.broker_generation
        && expected.configuration_generation == actual.configuration_generation
        && expected.session_fingerprint == actual.session_fingerprint
        && expected.lease_token == actual.lease_token
        && expected.session == actual.session.as_str()
}

/// Encode one typed control frame after bounded validation.
fn encode_control(kind: BrokerControlKind, payload: Vec<u8>) -> RelayResult<Vec<u8>> {
    BrokerFrame::control(kind, payload)
        .and_then(|frame| frame.encode())
        .map_err(protocol_error)
}

/// Read one complete bounded frame from a control/data stream.
async fn read_frame(stream: &mut TcpStream, magic: [u8; 4]) -> RelayResult<BrokerFrame> {
    timeout(BROKER_CONTROL_TIMEOUT, async {
        let mut header = [0_u8; BROKER_FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|error| RelayError::io("reading Broker frame header", error))?;
        let payload_len =
            u32::from_be_bytes(header[7..11].try_into().map_err(|_| RelayError::Manager {
                reason: "Broker frame header is invalid",
            })?) as usize;
        let total =
            BROKER_FRAME_HEADER_BYTES
                .checked_add(payload_len)
                .ok_or(RelayError::Manager {
                    reason: "Broker frame exceeds its bound",
                })?;
        if total > BROKER_MAX_FRAME_BYTES {
            return Err(RelayError::Manager {
                reason: "Broker frame exceeds its bound",
            });
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&header);
        bytes.resize(total, 0);
        stream
            .read_exact(&mut bytes[BROKER_FRAME_HEADER_BYTES..])
            .await
            .map_err(|error| RelayError::io("reading Broker frame payload", error))?;
        BrokerFrame::decode(&bytes, magic).map_err(protocol_error)
    })
    .await
    .map_err(|_| RelayError::Manager {
        reason: "Broker frame timed out",
    })?
}

/// Write one complete bounded frame to a control/data stream.
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> RelayResult<()> {
    timeout(BROKER_CONTROL_TIMEOUT, async {
        stream
            .write_all(bytes)
            .await
            .map_err(|error| RelayError::io("writing Broker frame", error))?;
        stream
            .flush()
            .await
            .map_err(|error| RelayError::io("flushing Broker frame", error))
    })
    .await
    .map_err(|_| RelayError::Manager {
        reason: "Broker frame write timed out",
    })?
}

/// Map an internal protocol error into a stable Relay error.
fn protocol_error(_: impl std::fmt::Debug) -> RelayError {
    RelayError::Manager {
        reason: "Broker protocol frame is invalid",
    }
}

/// Append a fixed-width array from a bounded payload.
fn take_array<const N: usize>(payload: &[u8], cursor: &mut usize) -> RelayResult<[u8; N]> {
    let end = cursor.checked_add(N).ok_or(RelayError::Manager {
        reason: "Broker payload is invalid",
    })?;
    let bytes = payload.get(*cursor..end).ok_or(RelayError::Manager {
        reason: "Broker payload is invalid",
    })?;
    *cursor = end;
    bytes.try_into().map_err(|_| RelayError::Manager {
        reason: "Broker payload is invalid",
    })
}

/// Read one big-endian u64 from a bounded payload.
fn take_u64(payload: &[u8], cursor: &mut usize) -> RelayResult<u64> {
    Ok(u64::from_be_bytes(take_array(payload, cursor)?))
}

/// Read one length-prefixed source-aligned session.
fn take_session(payload: &[u8], cursor: &mut usize) -> RelayResult<SessionName> {
    let length = *payload.get(*cursor).ok_or(RelayError::Manager {
        reason: "Broker session field is missing",
    })? as usize;
    *cursor += 1;
    if length == 0 {
        return Err(RelayError::InvalidConfiguration {
            field: "session",
            reason: "wire session must not be empty",
        });
    }
    let end = cursor.checked_add(length).ok_or(RelayError::Manager {
        reason: "Broker session field is invalid",
    })?;
    let bytes = payload.get(*cursor..end).ok_or(RelayError::Manager {
        reason: "Broker session field is invalid",
    })?;
    *cursor = end;
    let value = std::str::from_utf8(bytes).map_err(|_| RelayError::InvalidConfiguration {
        field: "session",
        reason: "wire session is not UTF-8",
    })?;
    SessionName::normalize(value)
}

/// Reject trailing bytes after a typed payload.
fn finish_payload(payload: &[u8], cursor: usize) -> RelayResult<()> {
    if cursor == payload.len() {
        Ok(())
    } else {
        Err(RelayError::Manager {
            reason: "Broker payload has trailing bytes",
        })
    }
}

struct EnsureRequest {
    request_id: [u8; 16],
    core_instance_id: [u8; 16],
    session: SessionName,
}

struct StatusRequest {
    request_id: [u8; 16],
    session: SessionName,
}
