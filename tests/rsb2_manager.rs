//! Integration coverage for the real same-binary RSB-2 child bootstrap path.

use herdr_dog_relay::{
    broker::{BROKER_DATA_PORT_BASE, BROKER_DATA_PORT_LAST},
    manager::{
        MANAGER_HEARTBEAT_INTERVAL_SECS, MANAGER_IDLE_GRACE_SECS, MANAGER_LEASE_EXPIRY_SECS,
        Manager,
    },
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
use tokio::net::UnixListener;

/// Create a short canonical temporary root so macOS Unix socket paths stay within SUN_LEN.
fn test_root() -> PathBuf {
    let root = fs::canonicalize("/tmp")
        .expect("canonicalize temporary directory")
        .join(format!("rsb2-int-{}", std::process::id()));
    fs::create_dir_all(&root).expect("create integration root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect root");
    root
}

/// Verifies that the production Manager completes a real same-binary child bootstrap and cleanup.
// TEST:relay/tests/rsb2_manager.rs[process_child_bootstrap_uses_real_binary]
#[tokio::test(flavor = "current_thread")]
async fn process_child_bootstrap_uses_real_binary() {
    let root = test_root();
    let herdr_root = root.join("config").join(if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    });
    fs::create_dir_all(&herdr_root).expect("create Herdr root");
    fs::set_permissions(&herdr_root, fs::Permissions::from_mode(0o700))
        .expect("protect Herdr root");
    let socket_path = herdr_root.join("herdr.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind fake Herdr socket");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).expect("protect socket");
    let uid = fs::symlink_metadata(&socket_path)
        .expect("socket metadata")
        .uid();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_herdogrelay"));
    let config = format!(
        "manager_root = {:?}\nherdr_config_root = {:?}\nchild_binary = {:?}\npreferred_broker_port = 18743\nbroker_port_attempts = 10\ndata_port_start = {BROKER_DATA_PORT_BASE}\ndata_port_end = {BROKER_DATA_PORT_LAST}\nheartbeat_interval_secs = {MANAGER_HEARTBEAT_INTERVAL_SECS}\nlease_expiry_secs = {MANAGER_LEASE_EXPIRY_SECS}\nidle_grace_secs = {MANAGER_IDLE_GRACE_SECS}\n",
        root.join("manager").to_string_lossy(),
        root.join("config").to_string_lossy(),
        binary.to_string_lossy(),
    );
    let config = herdr_dog_relay::manager::ManagerConfig::from_toml_str(&config)
        .expect("parse integration Manager config");
    let mut manager = Manager::open(config, uid).expect("open production Manager");
    let grant = manager
        .ensure("default", 100)
        .await
        .expect("ensure real child");
    assert_eq!(grant.data_port(), BROKER_DATA_PORT_BASE);
    manager.release(grant.token(), 130).expect("release lease");
    let report = manager.reap(430).await.expect("stop real child");
    assert_eq!(report.stopped_sessions.len(), 1);
    drop(listener);
    fs::remove_file(socket_path).expect("remove socket");
    fs::remove_dir_all(root).expect("remove integration root");
}
