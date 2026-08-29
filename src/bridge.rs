//! Bounded, protocol-agnostic bidirectional byte forwarding.

use crate::{
    config::{QRM_BUFFER_BYTES, QRM_IDLE_TIMEOUT_SECS},
    error::{RelayError, RelayResult},
};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::{self, Instant, Sleep},
};

/// The bounded resource policy used by one byte bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeLimits {
    /// The maximum per-direction read buffer.
    buffer_bytes: usize,
    /// The maximum whole-stream inactivity interval.
    idle_timeout: Duration,
}

impl BridgeLimits {
    /// Creates a bounded policy for QRM session streams.
    ///
    /// # Arguments
    ///
    /// * `buffer_bytes` - A non-zero buffer no larger than the QRM limit.
    /// * `idle_timeout` - A non-zero timeout no longer than the QRM limit.
    ///
    /// # Returns
    ///
    /// A bounded bridge policy or a redacted configuration error.
    pub fn new(buffer_bytes: usize, idle_timeout: Duration) -> RelayResult<Self> {
        if buffer_bytes == 0 || buffer_bytes > QRM_BUFFER_BYTES {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.buffer_bytes",
                reason: "must be between 1 and the QRM buffer limit",
            });
        }
        if idle_timeout.is_zero() || idle_timeout > Duration::from_secs(QRM_IDLE_TIMEOUT_SECS) {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.idle_timeout_secs",
                reason: "must be between 1 second and the QRM idle limit",
            });
        }
        Ok(Self {
            buffer_bytes,
            idle_timeout,
        })
    }

    /// Returns the exact QRM bridge policy.
    pub fn v1() -> Self {
        Self {
            buffer_bytes: QRM_BUFFER_BYTES,
            idle_timeout: Duration::from_secs(QRM_IDLE_TIMEOUT_SECS),
        }
    }

    /// Returns the configured per-direction buffer size.
    ///
    /// # Returns
    ///
    /// The bounded read buffer size in bytes.
    pub fn buffer_bytes(self) -> usize {
        self.buffer_bytes
    }

    /// Returns the configured whole-stream idle timeout.
    ///
    /// # Returns
    ///
    /// The bounded inactivity duration.
    pub fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }
}

/// The result of a bridge that ended after both directions reached EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeOutcome {
    /// Bytes copied from the network-side stream to the Unix-side stream.
    pub network_to_unix_bytes: u64,
    /// Bytes copied from the Unix-side stream to the network-side stream.
    pub unix_to_network_bytes: u64,
}

/// Runs bounded bidirectional forwarding until both streams close or a policy fails.
///
/// # Arguments
///
/// * `network` - The authenticated network-side byte stream.
/// * `unix` - The validated local Unix-side byte stream.
/// * `limits` - The bounded buffer and idle policy.
///
/// # Returns
///
/// Byte counts for a clean two-sided close, or a redacted forwarding error.
///
/// The function never interprets, logs, retries, or persists stream contents.
pub async fn run<N, U>(network: N, unix: U, limits: BridgeLimits) -> RelayResult<BridgeOutcome>
where
    N: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (network_read, network_write) = tokio::io::split(network);
    let (unix_read, unix_write) = tokio::io::split(unix);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let network_to_unix = forward_direction(
        network_read,
        unix_write,
        limits.buffer_bytes,
        "reading network stream",
        "writing Unix stream",
        activity_tx.clone(),
    );
    let unix_to_network = forward_direction(
        unix_read,
        network_write,
        limits.buffer_bytes,
        "reading Unix stream",
        "writing network stream",
        activity_tx,
    );
    tokio::pin!(network_to_unix);
    tokio::pin!(unix_to_network);
    let mut network_result = None;
    let mut unix_result = None;
    let mut idle = Box::pin(time::sleep(limits.idle_timeout));

    loop {
        tokio::select! {
            result = &mut network_to_unix, if network_result.is_none() => {
                network_result = Some(result);
            }
            result = &mut unix_to_network, if unix_result.is_none() => {
                unix_result = Some(result);
            }
            Some(()) = activity_rx.recv() => {
                reset_idle_timer(&mut idle, limits.idle_timeout);
            }
            () = &mut idle => {
                // Returning drops both pinned direction futures, so caller cancellation,
                // timeout, and internal errors all close workers with the bridge owner.
                return Err(RelayError::BridgeIdleTimeout);
            }
        }

        if let Some(Err(error)) = network_result.as_ref() {
            return Err(error.clone());
        }
        if let Some(Err(error)) = unix_result.as_ref() {
            return Err(error.clone());
        }
        if let (Some(Ok(network_to_unix_bytes)), Some(Ok(unix_to_network_bytes))) =
            (network_result.as_ref(), unix_result.as_ref())
        {
            return Ok(BridgeOutcome {
                network_to_unix_bytes: *network_to_unix_bytes,
                unix_to_network_bytes: *unix_to_network_bytes,
            });
        }
    }
}

/// Copies one direction with a fixed allocation and half-close propagation.
async fn forward_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_bytes: usize,
    read_operation: &'static str,
    write_operation: &'static str,
    activity_tx: mpsc::Sender<()>,
) -> RelayResult<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; buffer_bytes];
    let mut copied = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| RelayError::io(read_operation, error))?;
        if read == 0 {
            writer
                .shutdown()
                .await
                .map_err(|error| RelayError::io("shutting down bridge write half", error))?;
            return Ok(copied);
        }
        let _ = activity_tx.send(()).await;
        writer
            .write_all(&buffer[..read])
            .await
            .map_err(|error| RelayError::io(write_operation, error))?;
        let _ = activity_tx.send(()).await;
        copied += read as u64;
    }
}

/// Resets the single whole-stream idle timer after either direction is active.
fn reset_idle_timer(timer: &mut std::pin::Pin<Box<Sleep>>, timeout: Duration) {
    timer.as_mut().reset(Instant::now() + timeout);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::UnixSocketConnector;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // TEST:relay/src/bridge.rs[tests::qrm_limits_are_fixed]
    #[test]
    fn qrm_limits_are_fixed() {
        let limits = BridgeLimits::v1();
        assert_eq!(limits.buffer_bytes(), QRM_BUFFER_BYTES);
        assert_eq!(
            limits.idle_timeout(),
            Duration::from_secs(QRM_IDLE_TIMEOUT_SECS)
        );
    }

    // TEST:relay/src/bridge.rs[tests::invalid_limits_are_rejected]
    #[test]
    fn invalid_limits_are_rejected() {
        assert!(BridgeLimits::new(0, Duration::from_secs(1)).is_err());
        assert!(BridgeLimits::new(QRM_BUFFER_BYTES + 1, Duration::from_secs(1)).is_err());
        assert!(BridgeLimits::new(1, Duration::ZERO).is_err());
        assert!(BridgeLimits::new(1, Duration::from_secs(QRM_IDLE_TIMEOUT_SECS + 1)).is_err());
    }

    // TEST:relay/src/bridge.rs[tests::bridge_forwards_both_directions]
    #[tokio::test(flavor = "current_thread")]
    async fn bridge_forwards_both_directions() {
        let (network, mut network_peer) = tokio::io::duplex(256);
        let (unix, mut unix_peer) = tokio::io::duplex(256);
        let bridge = tokio::spawn(run(
            network,
            unix,
            BridgeLimits::new(32, Duration::from_secs(1)).expect("limits"),
        ));
        network_peer
            .write_all(b"to unix")
            .await
            .expect("network write");
        unix_peer
            .write_all(b"to network")
            .await
            .expect("Unix write");
        let mut unix_received = vec![0_u8; 7];
        let mut network_received = vec![0_u8; 10];
        unix_peer
            .read_exact(&mut unix_received)
            .await
            .expect("read Unix output");
        network_peer
            .read_exact(&mut network_received)
            .await
            .expect("read network output");
        network_peer.shutdown().await.expect("network EOF");
        unix_peer.shutdown().await.expect("Unix EOF");
        let outcome = bridge.await.expect("join bridge").expect("clean bridge");
        assert_eq!(&unix_received, b"to unix");
        assert_eq!(&network_received, b"to network");
        assert_eq!(outcome.network_to_unix_bytes, 7);
        assert_eq!(outcome.unix_to_network_bytes, 10);
    }

    // TEST:relay/src/bridge.rs[tests::validated_unix_stream_runs_through_bridge]
    #[tokio::test(flavor = "current_thread")]
    async fn validated_unix_stream_runs_through_bridge() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        // Keep the canonical Darwin Unix socket path below SUN_LEN with a short test directory.
        let directory = fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temporary directory")
            .join(format!("h{}{}", std::process::id(), nonce % 1_000_000));
        fs::create_dir(&directory).expect("create private integration directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("set private integration directory mode");
        let path = directory.join("herdr.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind integration socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set integration socket mode");
        let uid = fs::symlink_metadata(path.parent().expect("socket parent"))
            .expect("read integration parent")
            .uid();
        let connector = UnixSocketConnector::new(&path, uid).expect("create connector");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept integration socket");
            let mut request = [0_u8; 5];
            stream
                .read_exact(&mut request)
                .await
                .expect("read segmented request");
            assert_eq!(&request, b"hello");
            stream
                .write_all(b"wo")
                .await
                .expect("write first response segment");
            stream
                .write_all(b"rld")
                .await
                .expect("write second response segment");
            stream.shutdown().await.expect("close Unix write half");
        });
        let unix = connector.connect().await.expect("connect validated socket");
        let (network, mut peer) = tokio::io::duplex(32);
        let bridge = tokio::spawn(run(
            network,
            unix,
            BridgeLimits::new(4, Duration::from_secs(1)).expect("bridge limits"),
        ));
        peer.write_all(b"hello")
            .await
            .expect("write network request");
        peer.shutdown().await.expect("close network write half");
        let mut response = [0_u8; 5];
        peer.read_exact(&mut response)
            .await
            .expect("read network response");
        assert_eq!(&response, b"world");
        let mut eof = [0_u8; 1];
        assert_eq!(peer.read(&mut eof).await.expect("read network EOF"), 0);
        let outcome = bridge
            .await
            .expect("join integration bridge")
            .expect("bridge success");
        server.await.expect("join integration server");
        assert_eq!(outcome.network_to_unix_bytes, 5);
        assert_eq!(outcome.unix_to_network_bytes, 5);
        fs::remove_file(&path).expect("remove integration socket");
        fs::remove_dir(directory).expect("remove integration directory");
    }

    // TEST:relay/src/bridge.rs[tests::bridge_propagates_write_errors]
    #[tokio::test(flavor = "current_thread")]
    async fn bridge_propagates_write_errors() {
        let (network, mut peer) = tokio::io::duplex(32);
        let (unix, unix_peer) = tokio::io::duplex(32);
        drop(unix_peer);
        let bridge = tokio::spawn(run(
            network,
            unix,
            BridgeLimits::new(4, Duration::from_secs(1)).expect("bridge limits"),
        ));
        peer.write_all(b"x").await.expect("write failing payload");
        peer.shutdown()
            .await
            .expect("close failing network write half");
        let error = bridge
            .await
            .expect("join error bridge")
            .expect_err("bridge must report Unix write failure");
        assert!(matches!(error, RelayError::Io { .. }));
    }

    // TEST:relay/src/bridge.rs[tests::cancellation_drops_direction_futures]
    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_drops_direction_futures() {
        let (network, mut network_peer) = tokio::io::duplex(16);
        let (unix, mut unix_peer) = tokio::io::duplex(16);
        let bridge = tokio::spawn(run(network, unix, BridgeLimits::v1()));
        tokio::task::yield_now().await;
        bridge.abort();
        let _ = bridge.await;
        let mut network_eof = [0_u8; 1];
        let mut unix_eof = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), network_peer.read(&mut network_eof))
                .await
                .expect("network EOF timeout")
                .expect("network EOF read"),
            0
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), unix_peer.read(&mut unix_eof))
                .await
                .expect("Unix EOF timeout")
                .expect("Unix EOF read"),
            0
        );
    }

    // TEST:relay/src/bridge.rs[tests::idle_stream_is_terminated]
    #[tokio::test(flavor = "current_thread")]
    async fn idle_stream_is_terminated() {
        let (network, _network_peer) = tokio::io::duplex(16);
        let (unix, _unix_peer) = tokio::io::duplex(16);
        let error = run(
            network,
            unix,
            BridgeLimits::new(8, Duration::from_millis(20)).expect("limits"),
        )
        .await
        .expect_err("idle bridge must terminate");
        assert!(matches!(error, RelayError::BridgeIdleTimeout));
    }
}
