//! Fixed authenticated Relay handshake framing.

use crate::{
    config::{ListenerClass, V1_RELAY_PROTOCOL_VERSION},
    error::{RelayError, RelayResult},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The four-byte Relay handshake magic.
pub const RELAY_HANDSHAKE_MAGIC: [u8; 4] = *b"HDRL";
/// The server challenge message type.
pub const RELAY_HANDSHAKE_CHALLENGE: u8 = 0x01;
/// The client nonce-echo message type.
pub const RELAY_HANDSHAKE_RESPONSE: u8 = 0x02;
/// The server acknowledgement message type.
pub const RELAY_HANDSHAKE_ACKNOWLEDGEMENT: u8 = 0x03;
/// The number of bytes in the server challenge.
pub const RELAY_CHALLENGE_BYTES: usize = 40;
/// The number of bytes in the client response.
pub const RELAY_RESPONSE_BYTES: usize = 39;
/// The number of bytes in the server acknowledgement.
pub const RELAY_ACKNOWLEDGEMENT_BYTES: usize = 7;
/// The number of random bytes in one server challenge.
pub const RELAY_NONCE_BYTES: usize = 32;

/// Performs the server side of the fixed post-TLS Relay handshake.
///
/// # Arguments
///
/// * `stream` - The already authenticated TLS byte stream.
/// * `listener_class` - The class of the listener that accepted the stream.
///
/// # Returns
///
/// `Ok(())` after the client echoes the server challenge and the acknowledgement
/// is flushed, or a redacted handshake error.
pub async fn server_handshake<S>(stream: &mut S, listener_class: ListenerClass) -> RelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut challenge = [0_u8; RELAY_CHALLENGE_BYTES];
    challenge[..4].copy_from_slice(&RELAY_HANDSHAKE_MAGIC);
    challenge[4] = RELAY_HANDSHAKE_CHALLENGE;
    challenge[5..7].copy_from_slice(&V1_RELAY_PROTOCOL_VERSION.to_be_bytes());
    challenge[7] = listener_class.code();
    rand::fill(&mut challenge[8..]);
    stream
        .write_all(&challenge)
        .await
        .map_err(|error| RelayError::io("writing Relay challenge", error))?;
    stream
        .flush()
        .await
        .map_err(|error| RelayError::io("flushing Relay challenge", error))?;

    let mut response = [0_u8; RELAY_RESPONSE_BYTES];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| RelayError::io("reading Relay response", error))?;
    if response[..4] != RELAY_HANDSHAKE_MAGIC
        || response[4] != RELAY_HANDSHAKE_RESPONSE
        || response[5..7] != V1_RELAY_PROTOCOL_VERSION.to_be_bytes()
        || response[7..] != challenge[8..]
    {
        return Err(RelayError::RelayHandshake);
    }

    let mut acknowledgement = [0_u8; RELAY_ACKNOWLEDGEMENT_BYTES];
    acknowledgement[..4].copy_from_slice(&RELAY_HANDSHAKE_MAGIC);
    acknowledgement[4] = RELAY_HANDSHAKE_ACKNOWLEDGEMENT;
    acknowledgement[5..7].copy_from_slice(&V1_RELAY_PROTOCOL_VERSION.to_be_bytes());
    stream
        .write_all(&acknowledgement)
        .await
        .map_err(|error| RelayError::io("writing Relay acknowledgement", error))?;
    stream
        .flush()
        .await
        .map_err(|error| RelayError::io("flushing Relay acknowledgement", error))?;
    Ok(())
}

/// Performs the client side of the fixed handshake for in-crate integration tests.
///
/// This helper is crate-private so the relay does not expose a second client transport
/// API; the production client remains Core-owned.
#[cfg(test)]
pub(crate) async fn client_handshake<S>(
    stream: &mut S,
    expected_class: ListenerClass,
) -> RelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut challenge = [0_u8; RELAY_CHALLENGE_BYTES];
    stream
        .read_exact(&mut challenge)
        .await
        .map_err(|error| RelayError::io("reading Relay challenge", error))?;
    if challenge[..4] != RELAY_HANDSHAKE_MAGIC
        || challenge[4] != RELAY_HANDSHAKE_CHALLENGE
        || challenge[5..7] != V1_RELAY_PROTOCOL_VERSION.to_be_bytes()
        || challenge[7] != expected_class.code()
    {
        return Err(RelayError::RelayHandshake);
    }

    let mut response = [0_u8; RELAY_RESPONSE_BYTES];
    response[..4].copy_from_slice(&RELAY_HANDSHAKE_MAGIC);
    response[4] = RELAY_HANDSHAKE_RESPONSE;
    response[5..7].copy_from_slice(&V1_RELAY_PROTOCOL_VERSION.to_be_bytes());
    response[7..].copy_from_slice(&challenge[8..]);
    stream
        .write_all(&response)
        .await
        .map_err(|error| RelayError::io("writing Relay response", error))?;
    stream
        .flush()
        .await
        .map_err(|error| RelayError::io("flushing Relay response", error))?;

    let mut acknowledgement = [0_u8; RELAY_ACKNOWLEDGEMENT_BYTES];
    stream
        .read_exact(&mut acknowledgement)
        .await
        .map_err(|error| RelayError::io("reading Relay acknowledgement", error))?;
    if acknowledgement[..4] != RELAY_HANDSHAKE_MAGIC
        || acknowledgement[4] != RELAY_HANDSHAKE_ACKNOWLEDGEMENT
        || acknowledgement[5..7] != V1_RELAY_PROTOCOL_VERSION.to_be_bytes()
    {
        return Err(RelayError::RelayHandshake);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // TEST:relay/src/handshake.rs[tests::valid_handshake_completes]
    #[tokio::test(flavor = "current_thread")]
    async fn valid_handshake_completes() {
        let (mut server, mut client) = tokio::io::duplex(128);
        let server_task =
            tokio::spawn(
                async move { server_handshake(&mut server, ListenerClass::Tailscale).await },
            );
        client_handshake(&mut client, ListenerClass::Tailscale)
            .await
            .expect("valid handshake");
        server_task
            .await
            .expect("join server handshake")
            .expect("server handshake");
    }

    // TEST:relay/src/handshake.rs[tests::wrong_nonce_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn wrong_nonce_is_rejected() {
        let (mut server, mut client) = tokio::io::duplex(128);
        let server_task =
            tokio::spawn(
                async move { server_handshake(&mut server, ListenerClass::Tailscale).await },
            );
        let mut challenge = [0_u8; RELAY_CHALLENGE_BYTES];
        client
            .read_exact(&mut challenge)
            .await
            .expect("read challenge");
        challenge[8] ^= 1;
        let mut response = [0_u8; RELAY_RESPONSE_BYTES];
        response[..4].copy_from_slice(&RELAY_HANDSHAKE_MAGIC);
        response[4] = RELAY_HANDSHAKE_RESPONSE;
        response[5..7].copy_from_slice(&V1_RELAY_PROTOCOL_VERSION.to_be_bytes());
        response[7..].copy_from_slice(&challenge[8..]);
        client.write_all(&response).await.expect("write response");
        let error = server_task
            .await
            .expect("join server handshake")
            .expect_err("wrong nonce must fail");
        assert!(matches!(error, RelayError::RelayHandshake));
    }

    // TEST:relay/src/handshake.rs[tests::wrong_magic_is_rejected]
    #[tokio::test(flavor = "current_thread")]
    async fn wrong_magic_is_rejected() {
        let (mut server, mut client) = tokio::io::duplex(128);
        let server_task =
            tokio::spawn(
                async move { server_handshake(&mut server, ListenerClass::Tailscale).await },
            );
        let mut challenge = [0_u8; RELAY_CHALLENGE_BYTES];
        client
            .read_exact(&mut challenge)
            .await
            .expect("read challenge");
        let mut response = [0_u8; RELAY_RESPONSE_BYTES];
        response[4] = RELAY_HANDSHAKE_RESPONSE;
        response[5..7].copy_from_slice(&V1_RELAY_PROTOCOL_VERSION.to_be_bytes());
        response[7..].copy_from_slice(&challenge[8..]);
        client.write_all(&response).await.expect("write response");
        let error = server_task
            .await
            .expect("join server handshake")
            .expect_err("wrong magic must fail");
        assert!(matches!(error, RelayError::RelayHandshake));
    }
}
