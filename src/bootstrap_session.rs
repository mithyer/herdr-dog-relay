//! Relay-side HDB1 bootstrap stream dispatcher for local transport tests.
//!
//! The dispatcher composes the bounded HDB1 codec with the deterministic hidden-workspace fake.
//! It intentionally stops before QUIC ALPN dispatch, certificate issuance and Herdr I/O.

use std::{fmt, net::IpAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{
    bootstrap::{
        BootstrapRecovery, BootstrapStartRequest, CoreCertificateMetadata, RelayBootstrapError,
        RelayBootstrapVerifier,
    },
    bootstrap_wire::{
        self, HDB1_REJECTION_ALREADY_ACTIVE, HDB1_REJECTION_AUTHORITY_MISMATCH,
        HDB1_REJECTION_CODE_MISMATCH, HDB1_REJECTION_CODE_RATE_LIMITED, HDB1_REJECTION_EXPIRED,
        HDB1_REJECTION_INVALID_FIELD, HDB1_REJECTION_INVALID_STATE, HDB1_REJECTION_ISSUANCE_FAILED,
        HDB1_REJECTION_OVERFLOW, HDB1_REJECTION_RESOURCE_LIMITED, HDB1_REJECTION_WORKSPACE_FAILURE,
        Hdb1CoreIssuedPayload, Hdb1Error, Hdb1Frame, Hdb1Kind, Hdb1RejectedPayload,
        Hdb1ResultPayload, Hdb1StartPayload, Hdb1SubmitPayload,
    },
    enrollment::CsrDigest,
};

/// Maximum time allowed for one local HDB1 read or write operation.
pub(crate) const HDB1_SESSION_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Sanitized errors returned by the Relay HDB1 stream dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hdb1RelaySessionError {
    /// One bounded read or write exceeded its deadline.
    Timeout,
    /// The peer sent a malformed frame or payload.
    Wire(Hdb1Error),
}

impl fmt::Display for Hdb1RelaySessionError {
    /// Formats a stable error without payload, identifier or certificate data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Relay HDB1 stream operation timed out"),
            Self::Wire(error) => write!(formatter, "Relay HDB1 stream wire error: {error}"),
        }
    }
}

impl std::error::Error for Hdb1RelaySessionError {}

impl From<Hdb1Error> for Hdb1RelaySessionError {
    /// Map the bounded wire error without preserving raw payload details.
    fn from(error: Hdb1Error) -> Self {
        Self::Wire(error)
    }
}

/// Relay-side HDB1 dispatcher over one terminal generic byte stream.
pub(crate) struct RelayHdb1BootstrapSession;

impl RelayHdb1BootstrapSession {
    /// Serve one Start, Challenge, Submit and terminal response exchange.
    ///
    /// # Parameters
    /// * `verifier` - Relay-owned deterministic hidden-workspace authority fake.
    /// * `peer_ip` - Relay-observed peer IP used for bounded admission.
    /// * `configuration_generation` - Relay-local generation bound to the request context.
    /// * `now_epoch_seconds` - Deterministic current epoch second for all fake operations.
    /// * `stream` - One bounded asynchronous byte stream reserved for this attempt.
    ///
    /// # Returns
    /// Success after a terminal response is written, or a sanitized framing/transport error.
    // TEST:relay/src/bootstrap_session.rs[tests::start_submit_and_issue_round_trip]
    pub(crate) async fn serve<S>(
        verifier: &mut RelayBootstrapVerifier,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), Hdb1RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_inner(
            verifier,
            peer_ip,
            configuration_generation,
            now_epoch_seconds,
            stream,
        )
        .await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Execute the bounded Start/Challenge/Submit exchange after lifecycle cleanup is wrapped.
    async fn serve_inner<S>(
        verifier: &mut RelayBootstrapVerifier,
        peer_ip: IpAddr,
        configuration_generation: u64,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), Hdb1RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start_frame = read_frame(stream).await?;
        let start_payload: Hdb1StartPayload = start_frame
            .parse_json(Hdb1Kind::Start)
            .map_err(Hdb1RelaySessionError::from)?;
        let start = decode_start(start_payload, configuration_generation)?;
        let challenge = match verifier.start(peer_ip, start, now_epoch_seconds) {
            Ok(challenge) => challenge,
            Err(error) => {
                write_rejection(stream, rejection_code(error)).await?;
                close_stream(stream).await?;
                return Ok(());
            }
        };
        let challenge_payload = bootstrap_wire::Hdb1ChallengePayload::new(
            challenge.bootstrap_id.bytes(),
            challenge.challenge.bytes(),
            challenge.expires_at_epoch_seconds,
        )
        .map_err(Hdb1RelaySessionError::from)?;
        write_frame(
            stream,
            &Hdb1Frame::json(Hdb1Kind::Challenge, &challenge_payload)
                .map_err(Hdb1RelaySessionError::from)?,
        )
        .await?;

        let submit_frame = read_frame(stream).await?;
        let submit_payload: Hdb1SubmitPayload = submit_frame
            .parse_json(Hdb1Kind::Submit)
            .map_err(Hdb1RelaySessionError::from)?;
        let (bootstrap_id, submitted_challenge, code) = submit_payload
            .decode_fields()
            .map_err(Hdb1RelaySessionError::from)?;
        let result =
            match verifier.submit_wire(bootstrap_id, submitted_challenge, &code, now_epoch_seconds)
            {
                Ok(metadata) => {
                    let payload = Hdb1CoreIssuedPayload::new(
                        metadata.approval_id.bytes(),
                        metadata.core_identity.bytes(),
                        &synthetic_certificate_chain(&metadata),
                        metadata.not_after_epoch_seconds,
                    )
                    .map_err(Hdb1RelaySessionError::from)?;
                    Hdb1Frame::json(Hdb1Kind::CoreIssued, &payload)
                        .map_err(Hdb1RelaySessionError::from)?
                }
                Err(error) => {
                    let payload = Hdb1RejectedPayload::new(rejection_code(error))
                        .map_err(Hdb1RelaySessionError::from)?;
                    Hdb1Frame::json(Hdb1Kind::Rejected, &payload)
                        .map_err(Hdb1RelaySessionError::from)?
                }
            };
        write_frame(stream, &result).await?;
        close_stream(stream).await
    }

    /// Serve one exact-binding HDB1 recovery request and terminal Result response.
    ///
    /// # Parameters
    /// * `verifier` - Relay-owned deterministic hidden-workspace authority fake.
    /// * `now_epoch_seconds` - Deterministic current epoch second for recovery validation.
    /// * `stream` - Fresh bounded asynchronous byte stream reserved for recovery.
    ///
    /// # Returns
    /// Success after a sanitized pending, issued or rejected Result is written.
    // TEST:relay/src/bootstrap_session.rs[tests::reconcile_rejection_round_trip]
    pub(crate) async fn reconcile<S>(
        verifier: &mut RelayBootstrapVerifier,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), Hdb1RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::reconcile_inner(verifier, now_epoch_seconds, stream).await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Execute the bounded recovery exchange after lifecycle cleanup is wrapped.
    async fn reconcile_inner<S>(
        verifier: &mut RelayBootstrapVerifier,
        now_epoch_seconds: u64,
        stream: &mut S,
    ) -> Result<(), Hdb1RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let payload: bootstrap_wire::Hdb1ReconcilePayload = frame
            .parse_json(Hdb1Kind::Reconcile)
            .map_err(Hdb1RelaySessionError::from)?;
        let (approval_id, core_binding_digest, normalized_session) = payload
            .decode_fields()
            .map_err(Hdb1RelaySessionError::from)?;
        let recovery = match verifier.reconcile_wire(
            approval_id,
            core_binding_digest,
            &normalized_session,
            now_epoch_seconds,
        ) {
            Ok(recovery) => recovery,
            Err(error) => {
                write_rejection(stream, rejection_code(error)).await?;
                close_stream(stream).await?;
                return Ok(());
            }
        };
        let result = match recovery {
            BootstrapRecovery::Pending { .. } => Hdb1ResultPayload::new_pending(approval_id),
            BootstrapRecovery::Issued(metadata) => Hdb1ResultPayload::new_issued(
                metadata.approval_id.bytes(),
                metadata.core_identity.bytes(),
                &synthetic_certificate_chain(&metadata),
                metadata.not_after_epoch_seconds,
            ),
            BootstrapRecovery::Rejected { code } => {
                Hdb1ResultPayload::new_rejected(approval_id, code)
            }
        }
        .map_err(Hdb1RelaySessionError::from)?;
        write_frame(
            stream,
            &Hdb1Frame::json(Hdb1Kind::Result, &result).map_err(Hdb1RelaySessionError::from)?,
        )
        .await?;
        close_stream(stream).await
    }
}

/// Decode a wire Start and bind its opaque generation context to the local fake request.
fn decode_start(
    payload: Hdb1StartPayload,
    configuration_generation: u64,
) -> Result<BootstrapStartRequest, Hdb1RelaySessionError> {
    let (
        request_id,
        core_csr,
        app_csr_digest,
        normalized_session,
        core_binding_digest,
        wire_configuration_generation,
    ) = payload
        .decode_fields()
        .map_err(Hdb1RelaySessionError::from)?;
    if wire_configuration_generation != configuration_generation {
        return Err(Hdb1RelaySessionError::Wire(Hdb1Error::InvalidField));
    }
    let app_csr_digest = CsrDigest::from_bytes(app_csr_digest)
        .map_err(|_| Hdb1RelaySessionError::Wire(Hdb1Error::InvalidField))?;
    BootstrapStartRequest::new(
        request_id,
        core_csr,
        app_csr_digest,
        normalized_session,
        configuration_generation,
        core_binding_digest,
    )
    .map_err(|_| Hdb1RelaySessionError::Wire(Hdb1Error::InvalidField))
}

/// Map internal fake failures to the shared fixed HDB1 rejection registry.
fn rejection_code(error: RelayBootstrapError) -> u16 {
    match error {
        RelayBootstrapError::InvalidValue
        | RelayBootstrapError::InvalidSession
        | RelayBootstrapError::InvalidGeneration
        | RelayBootstrapError::InvalidCsr => HDB1_REJECTION_INVALID_FIELD,
        RelayBootstrapError::CapacityExhausted | RelayBootstrapError::PeerRateLimited => {
            HDB1_REJECTION_RESOURCE_LIMITED
        }
        RelayBootstrapError::AlreadyActive => HDB1_REJECTION_ALREADY_ACTIVE,
        RelayBootstrapError::NotFound
        | RelayBootstrapError::AuthorityMismatch
        | RelayBootstrapError::InvalidChallenge => HDB1_REJECTION_AUTHORITY_MISMATCH,
        RelayBootstrapError::Expired => HDB1_REJECTION_EXPIRED,
        RelayBootstrapError::CodeMismatch => HDB1_REJECTION_CODE_MISMATCH,
        RelayBootstrapError::CodeRateLimited => HDB1_REJECTION_CODE_RATE_LIMITED,
        RelayBootstrapError::WorkspaceFailure | RelayBootstrapError::CleanupPending => {
            HDB1_REJECTION_WORKSPACE_FAILURE
        }
        RelayBootstrapError::InvalidState | RelayBootstrapError::AlreadyTerminal => {
            HDB1_REJECTION_INVALID_STATE
        }
        RelayBootstrapError::IssuanceFailed => HDB1_REJECTION_ISSUANCE_FAILED,
        RelayBootstrapError::Overflow => HDB1_REJECTION_OVERFLOW,
    }
}

/// Build deterministic public-only placeholder certificates for the local fake adapter.
fn synthetic_certificate_chain(metadata: &CoreCertificateMetadata) -> Vec<Vec<u8>> {
    vec![
        metadata.core_identity.bytes().to_vec(),
        metadata.certificate_chain_digest.bytes().to_vec(),
    ]
}

/// Write one frame under the fixed per-operation timeout.
async fn write_frame<S>(stream: &mut S, frame: &Hdb1Frame) -> Result<(), Hdb1RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    timeout(
        HDB1_SESSION_IO_TIMEOUT,
        bootstrap_wire::write_frame(stream, frame),
    )
    .await
    .map_err(|_| Hdb1RelaySessionError::Timeout)?
    .map_err(Hdb1RelaySessionError::from)
}

/// Read one frame under the fixed per-operation timeout.
async fn read_frame<S>(stream: &mut S) -> Result<Hdb1Frame, Hdb1RelaySessionError>
where
    S: AsyncRead + Unpin,
{
    timeout(HDB1_SESSION_IO_TIMEOUT, bootstrap_wire::read_frame(stream))
        .await
        .map_err(|_| Hdb1RelaySessionError::Timeout)?
        .map_err(Hdb1RelaySessionError::from)
}

/// Write one fixed rejection response.
async fn write_rejection<S>(stream: &mut S, code: u16) -> Result<(), Hdb1RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    let payload = Hdb1RejectedPayload::new(code).map_err(Hdb1RelaySessionError::from)?;
    let frame =
        Hdb1Frame::json(Hdb1Kind::Rejected, &payload).map_err(Hdb1RelaySessionError::from)?;
    write_frame(stream, &frame).await
}

/// Close the stream after the terminal response.
async fn close_stream<S>(stream: &mut S) -> Result<(), Hdb1RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    timeout(HDB1_SESSION_IO_TIMEOUT, stream.shutdown())
        .await
        .map_err(|_| Hdb1RelaySessionError::Timeout)?
        .map_err(|_| Hdb1RelaySessionError::Wire(Hdb1Error::InvalidFrame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 44));

    /// Build a deterministic valid Start payload for Relay session tests.
    fn start_payload() -> Hdb1StartPayload {
        Hdb1StartPayload::new([1; 16], &[2; 32], [3; 32], "default".to_owned(), [4; 32], 1)
            .expect("start payload")
    }

    /// Build the fake request corresponding to the wire Start payload.
    fn start_request(payload: &Hdb1StartPayload) -> BootstrapStartRequest {
        let (
            request_id,
            core_csr,
            app_csr_digest,
            normalized_session,
            core_binding_digest,
            configuration_generation,
        ) = payload.decode_fields().expect("start fields");
        BootstrapStartRequest::new(
            request_id,
            core_csr,
            CsrDigest::from_bytes(app_csr_digest).expect("app digest"),
            normalized_session,
            configuration_generation,
            core_binding_digest,
        )
        .expect("start request")
    }

    /// Prove the Relay dispatcher composes Start, Challenge, Submit and CoreIssued.
    #[tokio::test]
    // TEST:relay/src/bootstrap_session.rs[tests::start_submit_and_issue_round_trip]
    async fn start_submit_and_issue_round_trip() {
        let payload = start_payload();
        let mut preview = RelayBootstrapVerifier::new([9; 32]).expect("preview verifier");
        let preview_challenge = preview
            .start(PEER, start_request(&payload), 100)
            .expect("preview start");
        let code = preview
            .test_code(preview_challenge.bootstrap_id)
            .expect("preview code");
        let (mut client, mut server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let mut verifier = RelayBootstrapVerifier::new([9; 32]).expect("server verifier");
            RelayHdb1BootstrapSession::serve(&mut verifier, PEER, 1, 100, &mut server_stream)
                .await
                .expect("serve");
        });
        bootstrap_wire::write_frame(
            &mut client,
            &Hdb1Frame::json(Hdb1Kind::Start, &payload).expect("start frame"),
        )
        .await
        .expect("start write");
        let challenge_frame = bootstrap_wire::read_frame(&mut client)
            .await
            .expect("challenge");
        let challenge: bootstrap_wire::Hdb1ChallengePayload = challenge_frame
            .parse_json(Hdb1Kind::Challenge)
            .expect("challenge payload");
        let (bootstrap_id, challenge_bytes, _) =
            challenge.decode_fields().expect("challenge fields");
        let submit = Hdb1SubmitPayload::new(bootstrap_id, challenge_bytes, &code).expect("submit");
        bootstrap_wire::write_frame(
            &mut client,
            &Hdb1Frame::json(Hdb1Kind::Submit, &submit).expect("submit frame"),
        )
        .await
        .expect("submit write");
        let issued_frame = bootstrap_wire::read_frame(&mut client)
            .await
            .expect("issued");
        let issued: bootstrap_wire::Hdb1CoreIssuedPayload = issued_frame
            .parse_json(Hdb1Kind::CoreIssued)
            .expect("issued payload");
        let (_, _, chain, _) = issued.decode_fields().expect("issued fields");
        assert_eq!(chain.len(), 2);
        server.await.expect("server task");
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("eof"), 0);
    }

    /// Prove an authority failure returns a fixed terminal rejection over HDB1.
    #[tokio::test]
    // TEST:relay/src/bootstrap_session.rs[tests::reconcile_rejection_round_trip]
    async fn reconcile_rejection_round_trip() {
        let (mut client, mut server_stream) = duplex(1024);
        let server = tokio::spawn(async move {
            let mut verifier = RelayBootstrapVerifier::new([11; 32]).expect("verifier");
            RelayHdb1BootstrapSession::reconcile(&mut verifier, 100, &mut server_stream)
                .await
                .expect("reconcile serve");
        });
        let payload =
            bootstrap_wire::Hdb1ReconcilePayload::new([12; 32], [13; 32], "default".to_owned())
                .expect("reconcile payload");
        bootstrap_wire::write_frame(
            &mut client,
            &Hdb1Frame::json(Hdb1Kind::Reconcile, &payload).expect("reconcile frame"),
        )
        .await
        .expect("reconcile write");
        let frame = bootstrap_wire::read_frame(&mut client)
            .await
            .expect("rejection");
        let rejection: bootstrap_wire::Hdb1RejectedPayload = frame
            .parse_json(Hdb1Kind::Rejected)
            .expect("rejection payload");
        rejection.validate().expect("rejection fields");
        assert_ne!(rejection.code, 0);
        server.await.expect("server task");
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("eof"), 0);
    }

    /// Prove an initial Submit frame is rejected before any workspace authority is used.
    #[tokio::test]
    // TEST:relay/src/bootstrap_session.rs[tests::out_of_order_frame_is_rejected]
    async fn out_of_order_frame_is_rejected() {
        let (mut client, mut server_stream) = duplex(1024);
        let server = tokio::spawn(async move {
            let mut verifier = RelayBootstrapVerifier::new([10; 32]).expect("verifier");
            RelayHdb1BootstrapSession::serve(&mut verifier, PEER, 1, 100, &mut server_stream).await
        });
        let submit = Hdb1SubmitPayload::new([1; 32], [2; 32], "000000").expect("submit");
        bootstrap_wire::write_frame(
            &mut client,
            &Hdb1Frame::json(Hdb1Kind::Submit, &submit).expect("submit frame"),
        )
        .await
        .expect("write");
        assert_eq!(
            server.await.expect("server task"),
            Err(Hdb1RelaySessionError::Wire(Hdb1Error::InvalidOrder))
        );
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("eof"), 0);
    }

    /// Prove malformed terminal responses cannot be mistaken for a successful issue.
    #[tokio::test]
    // TEST:relay/src/bootstrap_session.rs[tests::rejection_code_mapping_is_nonzero]
    async fn rejection_code_mapping_is_nonzero() {
        assert_ne!(rejection_code(RelayBootstrapError::InvalidValue), 0);
        assert_ne!(rejection_code(RelayBootstrapError::CleanupPending), 0);
        assert_ne!(rejection_code(RelayBootstrapError::IssuanceFailed), 0);
    }
}
