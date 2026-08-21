//! RSB-3 Relay-side Manager control listener and HDBD bridge tests.
//!
//! These tests exercise a real local Manager-backed control/data listener with a disposable Unix
//! socket. They do not deploy mb17, enable public listeners, or interpret Herdr payloads.

use herdr_dog_relay::{
    broker::{
        BROKER_CONTROL_MAGIC, BROKER_DATA_MAGIC, BrokerControlKind, BrokerDataKind, BrokerFrame,
    },
    control::BrokerControlServer,
    manager::{FakeChildSpawner, Manager, ManagerConfig},
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixListener},
    sync::Mutex,
};

const CORE_ID: [u8; 16] = [2; 16];
const BROKER_ID: [u8; 16] = [1; 16];
static TEST_LOCK: Mutex<()> = Mutex::const_new(());

/// Create a private test root without relying on repository paths.
fn test_root() -> PathBuf {
    let root = fs::canonicalize("/tmp")
        .expect("canonical temp directory")
        .join(format!(
            "herdr-dog-rsb3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
    fs::create_dir_all(&root).expect("test root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root permissions");
    root
}

/// Build a validated Manager configuration rooted in the disposable test directory.
fn test_config(root: &Path) -> ManagerConfig {
    let manager_root = root.join("manager");
    let herdr_root = root.join("config");
    ManagerConfig::from_toml_str(&format!(
        "manager_root = \"{}\"\nherdr_config_root = \"{}\"\nchild_binary = \"/bin/true\"\npreferred_broker_port = 18743\nbroker_port_attempts = 10\ndata_port_start = 18753\ndata_port_end = 18852\nheartbeat_interval_secs = 30\nlease_expiry_secs = 90\nidle_grace_secs = 300\n",
        manager_root.display(),
        herdr_root.display()
    ))
    .expect("Manager configuration")
}

/// Create one existing named Herdr session socket and its accepting listener.
fn bind_session(root: &Path, name: &str) -> UnixListener {
    let app_dir = if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    };
    let session_dir = root
        .join("config")
        .join(app_dir)
        .join("sessions")
        .join(name);
    fs::create_dir_all(&session_dir).expect("Herdr directory");
    fs::set_permissions(&session_dir, fs::Permissions::from_mode(0o700)).expect("session mode");
    let socket_path = session_dir.join("herdr.sock");
    let listener = UnixListener::bind(&socket_path).expect("Herdr socket");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("socket mode");
    listener
}

/// Create one existing default Herdr session socket and its accepting listener.
async fn test_manager(root: &Path) -> (Manager, UnixListener) {
    let listener = bind_session(root, "main");
    let app_dir = if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    };
    let socket_path = root
        .join("config")
        .join(app_dir)
        .join("sessions")
        .join("main")
        .join("herdr.sock");
    let uid = fs::symlink_metadata(&socket_path)
        .expect("socket metadata")
        .uid();
    let manager = Manager::with_spawner(test_config(root), uid, Arc::new(FakeChildSpawner::new()))
        .expect("Manager");
    (manager, listener)
}

/// Reopen a Manager over an existing disposable session after a process restart.
fn manager_for_existing(root: &Path) -> Manager {
    let app_dir = if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    };
    let socket_path = root
        .join("config")
        .join(app_dir)
        .join("sessions")
        .join("main")
        .join("herdr.sock");
    let uid = fs::symlink_metadata(socket_path)
        .expect("existing socket metadata")
        .uid();
    Manager::with_spawner(test_config(root), uid, Arc::new(FakeChildSpawner::new()))
        .expect("reopened Manager")
}

/// Read one complete bounded frame from a test connection.
async fn read_frame(stream: &mut TcpStream, magic: [u8; 4]) -> BrokerFrame {
    let mut header = [0_u8; 11];
    stream.read_exact(&mut header).await.expect("frame header");
    let payload_len = u32::from_be_bytes(header[7..11].try_into().expect("length")) as usize;
    let mut bytes = Vec::with_capacity(11 + payload_len);
    bytes.extend_from_slice(&header);
    bytes.resize(11 + payload_len, 0);
    stream
        .read_exact(&mut bytes[11..])
        .await
        .expect("frame payload");
    BrokerFrame::decode(&bytes, magic).expect("valid frame")
}

/// Write one complete bounded frame to a test connection.
async fn write_frame(stream: &mut TcpStream, frame: BrokerFrame) {
    stream
        .write_all(&frame.encode().expect("frame encode"))
        .await
        .expect("frame write");
}

/// Complete the Core side of the fixed HDRL challenge exchange.
async fn client_handshake(stream: &mut TcpStream) {
    let mut challenge = [0_u8; 40];
    stream.read_exact(&mut challenge).await.expect("challenge");
    assert_eq!(&challenge[..4], b"HDRL");
    let mut response = [0_u8; 39];
    response[..4].copy_from_slice(b"HDRL");
    response[4] = 2;
    response[5..7].copy_from_slice(&1_u16.to_be_bytes());
    response[7..].copy_from_slice(&challenge[8..]);
    stream.write_all(&response).await.expect("response");
    let mut ack = [0_u8; 7];
    stream.read_exact(&mut ack).await.expect("ack");
    assert_eq!(&ack[..4], b"HDRL");
    assert_eq!(ack[4], 3);
}

/// Build one fixed-width HDBD request from explicit authority fields.
fn binding_frame_with(
    core_id: [u8; 16],
    broker_id: [u8; 16],
    fingerprint: [u8; 32],
    generation: u64,
    configuration_generation: u64,
    token: [u8; 32],
    session: &str,
) -> BrokerFrame {
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(&core_id);
    payload.extend_from_slice(&broker_id);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&configuration_generation.to_be_bytes());
    payload.extend_from_slice(&fingerprint);
    payload.extend_from_slice(&token);
    payload.push(session.len() as u8);
    payload.extend_from_slice(session.as_bytes());
    BrokerFrame::data(BrokerDataKind::BindRequest, payload).expect("HDBD request")
}

/// Build the valid HDBD request for the default test authority.
fn binding_frame(fingerprint: [u8; 32], generation: u64, token: [u8; 32]) -> BrokerFrame {
    binding_frame_with(
        CORE_ID,
        BROKER_ID,
        fingerprint,
        generation,
        1,
        token,
        "main",
    )
}

/// Send one HDBD frame and return the Relay's one-byte decision without sending Herdr bytes.
async fn attempt_binding(data_port: u16, frame: BrokerFrame) -> u8 {
    let mut data = TcpStream::connect(("127.0.0.1", data_port))
        .await
        .expect("data connection");
    client_handshake(&mut data).await;
    write_frame(&mut data, frame).await;
    let response = read_frame(&mut data, BROKER_DATA_MAGIC).await;
    let decision = response.payload()[0];
    data.shutdown().await.expect("data close");
    decision
}

/// Build one HDBR lease-authority request for heartbeat or release.
///
/// The helper keeps the wire fields explicit so each mismatch test can alter exactly one
/// authority component without introducing a production-side generic serializer.
#[allow(clippy::too_many_arguments)]
fn control_authority_frame(
    kind: BrokerControlKind,
    request_id: [u8; 16],
    core_id: [u8; 16],
    broker_id: [u8; 16],
    generation: u64,
    configuration_generation: u64,
    fingerprint: [u8; 32],
    token: [u8; 32],
    session: &str,
) -> BrokerFrame {
    let mut payload = Vec::with_capacity(160);
    payload.extend_from_slice(&request_id);
    payload.extend_from_slice(&core_id);
    payload.extend_from_slice(&broker_id);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&configuration_generation.to_be_bytes());
    payload.extend_from_slice(&fingerprint);
    payload.extend_from_slice(&token);
    payload.push(session.len() as u8);
    payload.extend_from_slice(session.as_bytes());
    BrokerFrame::control(kind, payload).expect("authority frame")
}

/// Build one HDBR status request for a normalized session.
fn status_frame(request_id: [u8; 16], core_id: [u8; 16], session: &str) -> BrokerFrame {
    let mut payload = Vec::with_capacity(32 + session.len());
    payload.extend_from_slice(&request_id);
    payload.extend_from_slice(&core_id);
    payload.push(session.len() as u8);
    payload.extend_from_slice(session.as_bytes());
    BrokerFrame::control(BrokerControlKind::StatusRequest, payload).expect("status frame")
}

/// Send discovery and return the selected Broker/data metadata.
async fn discover(stream: &mut TcpStream) -> (u16, u64) {
    write_frame(
        stream,
        BrokerFrame::control(BrokerControlKind::DiscoveryRequest, Vec::new()).expect("discovery"),
    )
    .await;
    let response = read_frame(stream, BROKER_CONTROL_MAGIC).await;
    assert_eq!(
        response.control_kind(),
        Ok(BrokerControlKind::DiscoveryResponse)
    );
    let payload = response.payload();
    let control_port = u16::from_be_bytes(payload[24..26].try_into().expect("control port"));
    let generation = u64::from_be_bytes(payload[16..24].try_into().expect("generation"));
    (control_port, generation)
}

/// Request one session lease for an explicit Core authority and decode its opaque grant.
async fn ensure_for_session(
    stream: &mut TcpStream,
    core_id: [u8; 16],
    request_id: [u8; 16],
    session: &str,
) -> ([u8; 32], u64, [u8; 32], u16) {
    let mut payload = Vec::new();
    payload.extend_from_slice(&request_id);
    payload.extend_from_slice(&core_id);
    payload.push(session.len() as u8);
    payload.extend_from_slice(session.as_bytes());
    write_frame(
        stream,
        BrokerFrame::control(BrokerControlKind::EnsureRequest, payload).expect("ensure"),
    )
    .await;
    let response = read_frame(stream, BROKER_CONTROL_MAGIC).await;
    assert_eq!(
        response.control_kind(),
        Ok(BrokerControlKind::EnsureResponse)
    );
    let payload = response.payload();
    assert_eq!(payload[16], 0);
    let broker_id: [u8; 16] = payload[17..33].try_into().expect("broker ID");
    assert_eq!(broker_id, BROKER_ID);
    let generation = u64::from_be_bytes(payload[33..41].try_into().expect("generation"));
    let fingerprint = payload[41..73].try_into().expect("fingerprint");
    let data_port = u16::from_be_bytes(payload[73..75].try_into().expect("data port"));
    let token = payload[83..115].try_into().expect("token");
    (fingerprint, generation, token, data_port)
}

/// Request the default test session lease for the primary Core authority.
async fn ensure(stream: &mut TcpStream) -> ([u8; 32], u64, [u8; 32], u16) {
    ensure_for_session(stream, CORE_ID, [7; 16], "main").await
}

// TEST:relay/tests/rsb3_control.rs[broker_listener_exposes_bounded_discovery]
#[tokio::test(flavor = "current_thread")]
async fn broker_listener_exposes_bounded_discovery() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, _unix_listener) = test_manager(&root).await;
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            serve.serve_one().await.expect("control connection");
        }
    });
    let mut malformed = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("malformed connection");
    malformed.write_all(b"bad").await.expect("malformed bytes");
    malformed.shutdown().await.expect("malformed close");
    tokio::time::sleep(Duration::from_millis(5)).await;
    let mut stream = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("control connection");
    let (control_port, generation) = discover(&mut stream).await;
    assert_eq!(control_port, 18_743);
    assert!(generation > 0);
    task.abort();
    drop(server);
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[broker_multiple_leases_share_port_with_distinct_authority]
#[tokio::test(flavor = "current_thread")]
async fn broker_multiple_leases_share_port_with_distinct_authority() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, _unix_listener) = test_manager(&root).await;
    let _other_listener = bind_session(&root, "other");
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            serve.serve_one().await.expect("control connection");
        }
    });
    let mut first_control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("first ensure connection");
    let first = ensure(&mut first_control).await;
    drop(first_control);
    let mut second_control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("second ensure connection");
    let second = ensure_for_session(&mut second_control, [4; 16], [8; 16], "other").await;
    drop(second_control);
    assert_ne!(first.3, second.3);
    assert_ne!(first.2, second.2);
    assert_eq!(
        attempt_binding(first.3, binding_frame(first.0, first.1, first.2)).await,
        0
    );
    assert_eq!(
        attempt_binding(
            second.3,
            binding_frame_with([4; 16], BROKER_ID, second.0, second.1, 1, second.2, "other"),
        )
        .await,
        0
    );
    task.abort();
    drop(server);
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[broker_binding_mismatch_matrix_is_rejected_before_forward]
#[tokio::test(flavor = "current_thread")]
async fn broker_binding_mismatch_matrix_is_rejected_before_forward() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, _unix_listener) = test_manager(&root).await;
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            serve.serve_one().await.expect("control connection");
        }
    });
    let mut discovery = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("discovery connection");
    discover(&mut discovery).await;
    drop(discovery);
    let mut control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("ensure connection");
    let (fingerprint, generation, token, data_port) = ensure(&mut control).await;
    drop(control);
    let cases = [
        binding_frame_with(
            CORE_ID,
            BROKER_ID,
            fingerprint,
            generation,
            1,
            [8; 32],
            "main",
        ),
        binding_frame_with(
            [8; 16],
            BROKER_ID,
            fingerprint,
            generation,
            1,
            token,
            "main",
        ),
        binding_frame_with(CORE_ID, [8; 16], fingerprint, generation, 1, token, "main"),
        binding_frame_with(
            CORE_ID,
            BROKER_ID,
            fingerprint,
            generation + 1,
            1,
            token,
            "main",
        ),
        binding_frame_with(
            CORE_ID,
            BROKER_ID,
            fingerprint,
            generation,
            2,
            token,
            "main",
        ),
        binding_frame_with(CORE_ID, BROKER_ID, [8; 32], generation, 1, token, "main"),
        binding_frame_with(
            CORE_ID,
            BROKER_ID,
            fingerprint,
            generation,
            1,
            token,
            "other",
        ),
    ];
    for frame in cases {
        assert_ne!(attempt_binding(data_port, frame).await, 0);
    }
    task.abort();
    drop(server);
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[broker_restart_rejects_old_authority]
#[tokio::test(flavor = "current_thread")]
async fn broker_restart_rejects_old_authority() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, _unix_listener) = test_manager(&root).await;
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            serve.serve_one().await.expect("control connection");
        }
    });
    let mut control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("ensure connection");
    let (fingerprint, generation, token, data_port) = ensure(&mut control).await;
    drop(control);
    task.abort();
    drop(server);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let restarted = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager_for_existing(&root),
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("restarted Broker server"),
    );
    let serve = restarted.clone();
    let restarted_task = tokio::spawn(async move {
        loop {
            serve
                .serve_one()
                .await
                .expect("restarted control connection");
        }
    });
    let mut reensure = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("restarted ensure connection");
    let (_new_fingerprint, new_generation, _new_token, new_data_port) = ensure(&mut reensure).await;
    assert!(new_generation > generation);
    assert_eq!(new_data_port, data_port);
    drop(reensure);
    assert_ne!(
        attempt_binding(data_port, binding_frame(fingerprint, generation, token)).await,
        0
    );
    restarted_task.abort();
    drop(restarted);
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[broker_expired_authority_and_data_listener_are_reaped]
#[tokio::test(flavor = "current_thread")]
async fn broker_expired_authority_and_data_listener_are_reaped() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, _unix_listener) = test_manager(&root).await;
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            serve.serve_one().await.expect("control connection");
        }
    });
    let mut control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("ensure connection");
    let (fingerprint, generation, token, data_port) = ensure(&mut control).await;
    drop(control);
    let now = herdr_dog_relay::manager::epoch_seconds().expect("clock");
    server
        .reap_once(now + 91)
        .await
        .expect("reap expired lease");
    assert_ne!(
        attempt_binding(data_port, binding_frame(fingerprint, generation, token)).await,
        0
    );
    server
        .reap_once(now + 391)
        .await
        .expect("reap idle data listener");
    assert!(TcpStream::connect(("127.0.0.1", data_port)).await.is_err());
    let mut reensure = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("reensure connection");
    let (_fingerprint, _generation, _token, reallocated_port) = ensure(&mut reensure).await;
    assert_eq!(reallocated_port, data_port);
    drop(reensure);
    task.abort();
    drop(server);
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[bound_data_stream_requires_live_lease]
#[tokio::test(flavor = "current_thread")]
async fn bound_data_stream_requires_live_lease() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (mut manager, _unix_listener) = test_manager(&root).await;
    let now = herdr_dog_relay::manager::epoch_seconds().expect("clock");
    let grant = manager.ensure("main", now).await.expect("lease");
    manager
        .open_bound_stream(grant.token(), grant.session(), now)
        .await
        .expect("live bound stream");
    manager.reap(now + 91).await.expect("reap expired lease");
    assert!(
        manager
            .open_bound_stream(grant.token(), grant.session(), now + 91)
            .await
            .is_err()
    );
    fs::remove_dir_all(root).expect("remove test root");
}

// TEST:relay/tests/rsb3_control.rs[broker_control_round_trip_and_hdbd_gate]
#[tokio::test(flavor = "current_thread")]
async fn broker_control_round_trip_and_hdbd_gate() {
    let _guard = TEST_LOCK.lock().await;
    let root = test_root();
    let (manager, unix_listener) = test_manager(&root).await;
    let server = Arc::new(
        BrokerControlServer::bind_with_instance_id(
            manager,
            "127.0.0.1:18743".parse().expect("control address"),
            BROKER_ID,
        )
        .await
        .expect("Broker server"),
    );
    let serve = server.clone();
    let task = tokio::spawn(async move {
        loop {
            if let Err(error) = serve.serve_one().await {
                panic!("control connection: {error}");
            }
        }
    });
    let unix_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = unix_listener.accept().await.expect("Unix accept");
            let mut request = [0_u8; 5];
            if stream.read_exact(&mut request).await.is_ok() && request == *b"hello" {
                stream.write_all(b"world").await.expect("Unix response");
                return;
            }
        }
    });

    let mut control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("control connection");
    let (_control_port, _generation) = discover(&mut control).await;
    drop(control);
    let mut control = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("ensure control connection");
    let (fingerprint, generation, token, data_port) = ensure(&mut control).await;
    assert!(generation > 0);
    assert!((18_753..=18_852).contains(&data_port));
    drop(control);

    let mut data = TcpStream::connect(("127.0.0.1", data_port))
        .await
        .expect("data connection");
    client_handshake(&mut data).await;
    write_frame(&mut data, binding_frame(fingerprint, generation, token)).await;
    let binding_response = read_frame(&mut data, BROKER_DATA_MAGIC).await;
    assert_eq!(
        binding_response.data_kind(),
        Ok(BrokerDataKind::BindResponse)
    );
    assert_eq!(binding_response.payload()[0], 0);
    data.write_all(b"hello").await.expect("network bytes");
    let mut response = [0_u8; 5];
    data.read_exact(&mut response).await.expect("bridged bytes");
    assert_eq!(&response, b"world");
    data.shutdown().await.expect("data close");

    let mut heartbeat = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("heartbeat connection");
    write_frame(
        &mut heartbeat,
        control_authority_frame(
            BrokerControlKind::HeartbeatRequest,
            [9; 16],
            CORE_ID,
            BROKER_ID,
            generation,
            1,
            fingerprint,
            token,
            "main",
        ),
    )
    .await;
    let heartbeat_response = read_frame(&mut heartbeat, BROKER_CONTROL_MAGIC).await;
    assert_eq!(
        heartbeat_response.control_kind(),
        Ok(BrokerControlKind::HeartbeatResponse)
    );
    assert_eq!(heartbeat_response.payload()[16], 0);
    assert_eq!(
        u32::from_be_bytes(
            heartbeat_response.payload()[17..21]
                .try_into()
                .expect("TTL")
        ),
        90
    );
    drop(heartbeat);

    let mut status = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("status connection");
    write_frame(&mut status, status_frame([10; 16], CORE_ID, "main")).await;
    let ready_status = read_frame(&mut status, BROKER_CONTROL_MAGIC).await;
    assert_eq!(
        ready_status.control_kind(),
        Ok(BrokerControlKind::StatusResponse)
    );
    assert_eq!(ready_status.payload()[16], 4);
    drop(status);

    let mut release = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("release connection");
    write_frame(
        &mut release,
        control_authority_frame(
            BrokerControlKind::ReleaseRequest,
            [11; 16],
            CORE_ID,
            BROKER_ID,
            generation,
            1,
            fingerprint,
            token,
            "main",
        ),
    )
    .await;
    let released = read_frame(&mut release, BROKER_CONTROL_MAGIC).await;
    assert_eq!(
        released.control_kind(),
        Ok(BrokerControlKind::ReleaseResponse)
    );
    assert_eq!(released.payload()[16], 0);
    drop(release);

    let mut second_release = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("second release connection");
    write_frame(
        &mut second_release,
        control_authority_frame(
            BrokerControlKind::ReleaseRequest,
            [12; 16],
            CORE_ID,
            BROKER_ID,
            generation,
            1,
            fingerprint,
            token,
            "main",
        ),
    )
    .await;
    let already_released = read_frame(&mut second_release, BROKER_CONTROL_MAGIC).await;
    assert_eq!(already_released.payload()[16], 1);
    drop(second_release);

    let mut idle_status = TcpStream::connect("127.0.0.1:18743")
        .await
        .expect("idle status connection");
    write_frame(&mut idle_status, status_frame([13; 16], CORE_ID, "main")).await;
    let idle = read_frame(&mut idle_status, BROKER_CONTROL_MAGIC).await;
    assert_eq!(idle.payload()[16], 3);
    drop(idle_status);

    unix_task.await.expect("Unix bridge task");
    task.abort();
    drop(server);
    fs::remove_dir_all(root).expect("remove test root");
}
