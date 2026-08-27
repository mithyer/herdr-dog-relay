//! Relay-side generic HDE3 enrollment session dispatcher for local contract tests.
//!
//! The dispatcher validates request phases and writes sanitized HDE3 responses over one terminal
//! generic byte stream. It deliberately stops before QUIC, TLS, certificate issuance and App
//! allowlist behavior.

use std::{fmt, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::enrollment_v3_wire::{
    self, Hde3ApprovalChallengePayload, Hde3ApprovalStartPayload, Hde3ApprovalSubmitPayload,
    Hde3ConfirmPersistedPayload, Hde3Error, Hde3FirstAppSubmitPayload, Hde3Frame, Hde3Kind,
    Hde3ReconcilePayload, Hde3RejectedPayload, Hde3RenewPayload, Hde3ResultPayload,
};

/// Maximum time allowed for one HDE3 read, write or terminal shutdown operation.
pub(crate) const HDE3_SESSION_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Sanitized errors returned by the Relay HDE3 session dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hde3RelaySessionError {
    /// A bounded session operation exceeded its deadline.
    Timeout,
    /// The peer sent a malformed frame, payload or phase transition.
    Wire(Hde3Error),
}

impl fmt::Display for Hde3RelaySessionError {
    /// Formats a stable error without payload, identifier or certificate data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Relay HDE3 session operation timed out"),
            Self::Wire(error) => write!(formatter, "Relay HDE3 session wire error: {error}"),
        }
    }
}

impl std::error::Error for Hde3RelaySessionError {}

impl From<Hde3Error> for Hde3RelaySessionError {
    /// Maps the bounded codec error without preserving payload details.
    fn from(error: Hde3Error) -> Self {
        Self::Wire(error)
    }
}

/// Sanitized terminal response selected by a local Relay contract fake.
pub(crate) enum Hde3ServerResponse {
    /// A validated Result response, including pending, issued, active or rejected status.
    Result(Hde3ResultPayload),
    /// A fixed terminal rejection frame without an approval identifier.
    Rejected(Hde3RejectedPayload),
}

impl fmt::Debug for Hde3ServerResponse {
    /// Reports response kind without exposing public certificate or identity material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Result(_) => "Result",
            Self::Rejected(_) => "Rejected",
        })
    }
}

/// Relay-side HDE3 dispatcher over one terminal generic byte stream.
pub(crate) struct RelayHde3EnrollmentSession;

impl RelayHde3EnrollmentSession {
    /// Serves one first-App request and a terminal Result or Rejected response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for this operation.
    /// * `response` - Sanitized local response selected by the contract fake.
    ///
    /// # Returns
    /// Success after the terminal response is written and the stream is closed.
    // TEST:relay/src/enrollment_v3_session.rs[tests::first_app_submit_round_trip]
    pub(crate) async fn serve_first_app<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_first_app_inner(stream, response).await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Serves one later ApprovalStart/Challenge/ApprovalSubmit exchange.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for this approval.
    /// * `approval_id` - Relay-minted approval identifier for the challenge.
    /// * `challenge` - Relay-minted one-time challenge.
    /// * `expires_at_epoch_seconds` - Protected challenge expiry.
    /// * `response` - Sanitized terminal response after the code submission.
    ///
    /// # Returns
    /// Success after the terminal response is written and the stream is closed.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_approval]
    pub(crate) async fn serve_approval<S>(
        stream: &mut S,
        approval_id: [u8; 32],
        challenge: [u8; 32],
        expires_at_epoch_seconds: u64,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_approval_inner(
            stream,
            approval_id,
            challenge,
            expires_at_epoch_seconds,
            response,
        )
        .await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Serves one exact-binding Reconcile request and terminal Result response.
    ///
    /// # Parameters
    /// * `stream` - One fresh bounded asynchronous stream reserved for recovery.
    /// * `response` - Sanitized pending, issued, active or rejected response.
    ///
    /// # Returns
    /// Success after the terminal response is written and the stream is closed.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_reconcile]
    pub(crate) async fn serve_reconcile<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_reconcile_inner(stream, response).await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Serves one ConfirmPersisted request and terminal Result response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for confirmation.
    /// * `response` - Sanitized active or rejected response.
    ///
    /// # Returns
    /// Success after the terminal response is written and the stream is closed.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_confirm]
    pub(crate) async fn serve_confirm_persisted<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_confirm_persisted_inner(stream, response).await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Serves one same-key Renew request and terminal Result response.
    ///
    /// # Parameters
    /// * `stream` - One bounded asynchronous stream reserved for renewal.
    /// * `response` - Sanitized pending, issued, active or rejected response.
    ///
    /// # Returns
    /// Success after the terminal response is written and the stream is closed.
    // TEST:core/tests/hde3_relay_loopback.rs[core_and_relay_compose_renew]
    pub(crate) async fn serve_renew<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = Self::serve_renew_inner(stream, response).await;
        if result.is_err() {
            let _ = close_stream(stream).await;
        }
        result
    }

    /// Validates a first-App request before sending the selected response.
    async fn serve_first_app_inner<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let payload: Hde3FirstAppSubmitPayload = frame.parse_json(Hde3Kind::FirstAppSubmit)?;
        let (approval_id, _, _) = payload.decode_fields()?;
        write_response(stream, response, Some(approval_id)).await
    }

    /// Validates the two-phase later approval exchange before responding.
    async fn serve_approval_inner<S>(
        stream: &mut S,
        approval_id: [u8; 32],
        challenge: [u8; 32],
        expires_at_epoch_seconds: u64,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let start: Hde3ApprovalStartPayload = frame.parse_json(Hde3Kind::ApprovalStart)?;
        start.validate()?;
        let expected_app_csr_digest = start.app_csr_digest()?;
        let challenge_payload =
            Hde3ApprovalChallengePayload::new(approval_id, challenge, expires_at_epoch_seconds)?;
        let challenge_frame = Hde3Frame::json(Hde3Kind::ApprovalChallenge, &challenge_payload)?;
        write_frame(stream, &challenge_frame).await?;

        let frame = read_frame(stream).await?;
        let submit: Hde3ApprovalSubmitPayload = frame.parse_json(Hde3Kind::ApprovalSubmit)?;
        let (submitted_approval_id, submitted_challenge, _, _, submitted_csr_digest) =
            submit.decode_fields()?;
        if submitted_approval_id != approval_id
            || submitted_challenge != challenge
            || submitted_csr_digest != expected_app_csr_digest
        {
            return Err(Hde3RelaySessionError::Wire(Hde3Error::InvalidField));
        }
        write_response(stream, response, Some(approval_id)).await
    }

    /// Validates an exact-binding reconciliation request before responding.
    async fn serve_reconcile_inner<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let payload: Hde3ReconcilePayload = frame.parse_json(Hde3Kind::Reconcile)?;
        payload.validate()?;
        let approval_id = payload.approval_id()?;
        write_response(stream, response, Some(approval_id)).await
    }

    /// Validates a persisted-confirmation request before responding.
    async fn serve_confirm_persisted_inner<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let payload =
            frame.parse_json::<Hde3ConfirmPersistedPayload>(Hde3Kind::ConfirmPersisted)?;
        payload.validate()?;
        let approval_id = payload.approval_id()?;
        write_response(stream, response, Some(approval_id)).await
    }

    /// Validates a same-key renewal request before responding.
    async fn serve_renew_inner<S>(
        stream: &mut S,
        response: Hde3ServerResponse,
    ) -> Result<(), Hde3RelaySessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = read_frame(stream).await?;
        let payload: Hde3RenewPayload = frame.parse_json(Hde3Kind::Renew)?;
        payload.validate()?;
        write_response(stream, response, None).await
    }
}

/// Validates and writes one sanitized HDE3 response, including approval correlation when present.
async fn write_response<S>(
    stream: &mut S,
    response: Hde3ServerResponse,
    expected_approval_id: Option<[u8; 32]>,
) -> Result<(), Hde3RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    let frame = match response {
        Hde3ServerResponse::Result(payload) => {
            payload.validate()?;
            let approval_id = payload.approval_id()?;
            if expected_approval_id.is_some_and(|expected| expected != approval_id) {
                return Err(Hde3RelaySessionError::Wire(Hde3Error::InvalidField));
            }
            Hde3Frame::json(Hde3Kind::Result, &payload)?
        }
        Hde3ServerResponse::Rejected(payload) => {
            payload.validate()?;
            Hde3Frame::json(Hde3Kind::Rejected, &payload)?
        }
    };
    write_frame(stream, &frame).await?;
    close_stream(stream).await
}

/// Writes one HDE3 frame under the fixed operation deadline.
async fn write_frame<S>(stream: &mut S, frame: &Hde3Frame) -> Result<(), Hde3RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    timeout(
        HDE3_SESSION_IO_TIMEOUT,
        enrollment_v3_wire::write_frame(stream, frame),
    )
    .await
    .map_err(|_| Hde3RelaySessionError::Timeout)?
    .map_err(Hde3RelaySessionError::from)
}

/// Reads one HDE3 frame under the fixed operation deadline.
async fn read_frame<S>(stream: &mut S) -> Result<Hde3Frame, Hde3RelaySessionError>
where
    S: AsyncRead + Unpin,
{
    timeout(
        HDE3_SESSION_IO_TIMEOUT,
        enrollment_v3_wire::read_frame(stream),
    )
    .await
    .map_err(|_| Hde3RelaySessionError::Timeout)?
    .map_err(Hde3RelaySessionError::from)
}

/// Closes the terminal stream under the fixed shutdown deadline.
async fn close_stream<S>(stream: &mut S) -> Result<(), Hde3RelaySessionError>
where
    S: AsyncWrite + Unpin,
{
    timeout(HDE3_SESSION_IO_TIMEOUT, stream.shutdown())
        .await
        .map_err(|_| Hde3RelaySessionError::Timeout)?
        .map_err(|_| Hde3RelaySessionError::Wire(Hde3Error::InvalidFrame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_v3_wire::Hde3IssuedInput;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, duplex};

    /// Compute the digest required by the HDE3 CSR binding.
    fn csr_digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// Build a bounded public-only HDE3 issued result for dispatcher tests.
    fn issued_result(approval_id: [u8; 32]) -> Hde3ResultPayload {
        Hde3ResultPayload::new_issued(Hde3IssuedInput {
            approval_id,
            app_identity: [2; 32],
            certificate_chain: &[vec![3; 8], vec![4; 8]],
            certificate_fingerprint: [5; 32],
            certificate_chain_digest: [6; 32],
            not_after_epoch_seconds: 900,
            configuration_generation: 1,
            active: false,
        })
        .expect("issued result")
    }

    /// Prove a first-App request is validated before a correlated Result is emitted.
    #[tokio::test]
    // TEST:relay/src/enrollment_v3_session.rs[tests::first_app_submit_round_trip]
    async fn first_app_submit_round_trip() {
        let approval_id = [1; 32];
        let app_csr = b"app-csr";
        let request = Hde3FirstAppSubmitPayload {
            approval_id: URL_SAFE_NO_PAD.encode(approval_id),
            app_csr: URL_SAFE_NO_PAD.encode(app_csr),
            app_csr_digest: hex_digest(&csr_digest(app_csr)),
        };
        let frame = Hde3Frame::json(Hde3Kind::FirstAppSubmit, &request).expect("request frame");
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            RelayHde3EnrollmentSession::serve_first_app(
                &mut server,
                Hde3ServerResponse::Result(issued_result(approval_id)),
            )
            .await
            .expect("serve first app");
        });
        enrollment_v3_wire::write_frame(&mut client, &frame)
            .await
            .expect("request write");
        let response = enrollment_v3_wire::read_frame(&mut client)
            .await
            .expect("response frame");
        assert_eq!(response.kind(), Hde3Kind::Result);
        let payload: Hde3ResultPayload = response.parse_json(Hde3Kind::Result).expect("result");
        assert_eq!(payload.approval_id().expect("approval"), approval_id);
        let mut eof = [0_u8; 1];
        assert_eq!(client.read(&mut eof).await.expect("terminal eof"), 0);
        server_task.await.expect("server task");
    }

    /// Prove the Relay rejects a validly encoded ApprovalSubmit whose CSR differs from ApprovalStart.
    #[tokio::test]
    // TEST:relay/src/enrollment_v3_session.rs[tests::relay_rejects_approval_csr_mismatch]
    async fn relay_rejects_approval_csr_mismatch() {
        let approval_id = [1; 32];
        let challenge = [2; 32];
        let expected_csr = b"expected-app-csr";
        let submitted_csr = b"different-app-csr";
        let start = Hde3ApprovalStartPayload {
            app_csr_digest: hex_digest(&csr_digest(expected_csr)),
            normalized_session: "default".to_owned(),
            core_binding_digest: hex_digest(&[7; 32]),
            configuration_generation: 1,
        };
        let start_frame = Hde3Frame::json(Hde3Kind::ApprovalStart, &start).expect("start frame");
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            RelayHde3EnrollmentSession::serve_approval(
                &mut server,
                approval_id,
                challenge,
                700,
                Hde3ServerResponse::Result(issued_result(approval_id)),
            )
            .await
        });

        enrollment_v3_wire::write_frame(&mut client, &start_frame)
            .await
            .expect("start write");
        let challenge_frame = enrollment_v3_wire::read_frame(&mut client)
            .await
            .expect("challenge frame");
        assert_eq!(challenge_frame.kind(), Hde3Kind::ApprovalChallenge);

        let submit = Hde3ApprovalSubmitPayload {
            approval_id: URL_SAFE_NO_PAD.encode(approval_id),
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            code: "123456".to_owned(),
            app_csr: URL_SAFE_NO_PAD.encode(submitted_csr),
            app_csr_digest: hex_digest(&csr_digest(submitted_csr)),
        };
        let submit_frame =
            Hde3Frame::json(Hde3Kind::ApprovalSubmit, &submit).expect("submit frame");
        enrollment_v3_wire::write_frame(&mut client, &submit_frame)
            .await
            .expect("submit write");

        assert_eq!(
            server_task.await.expect("server task"),
            Err(Hde3RelaySessionError::Wire(Hde3Error::InvalidField))
        );
    }

    /// Prove the Relay rejects a valid ApprovalSubmit with a mismatched approval identifier.
    #[tokio::test]
    // TEST:relay/src/enrollment_v3_session.rs[tests::relay_rejects_approval_id_mismatch]
    async fn relay_rejects_approval_id_mismatch() {
        let approval_id = [1; 32];
        let wrong_approval_id = [9; 32];
        let challenge = [2; 32];
        let app_csr = b"approval-id-csr";
        let start = Hde3ApprovalStartPayload {
            app_csr_digest: hex_digest(&csr_digest(app_csr)),
            normalized_session: "default".to_owned(),
            core_binding_digest: hex_digest(&[7; 32]),
            configuration_generation: 1,
        };
        let start_frame = Hde3Frame::json(Hde3Kind::ApprovalStart, &start).expect("start frame");
        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            RelayHde3EnrollmentSession::serve_approval(
                &mut server,
                approval_id,
                challenge,
                700,
                Hde3ServerResponse::Result(issued_result(approval_id)),
            )
            .await
        });

        enrollment_v3_wire::write_frame(&mut client, &start_frame)
            .await
            .expect("start write");
        let challenge_frame = enrollment_v3_wire::read_frame(&mut client)
            .await
            .expect("challenge frame");
        assert_eq!(challenge_frame.kind(), Hde3Kind::ApprovalChallenge);

        let submit = Hde3ApprovalSubmitPayload {
            approval_id: URL_SAFE_NO_PAD.encode(wrong_approval_id),
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            code: "123456".to_owned(),
            app_csr: URL_SAFE_NO_PAD.encode(app_csr),
            app_csr_digest: hex_digest(&csr_digest(app_csr)),
        };
        let submit_frame =
            Hde3Frame::json(Hde3Kind::ApprovalSubmit, &submit).expect("submit frame");
        enrollment_v3_wire::write_frame(&mut client, &submit_frame)
            .await
            .expect("submit write");

        assert_eq!(
            server_task.await.expect("server task"),
            Err(Hde3RelaySessionError::Wire(Hde3Error::InvalidField))
        );
    }

    /// Convert a fixed digest to the lowercase hexadecimal form used by HDE3 test payloads.
    fn hex_digest(value: &[u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in value {
            output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
        output
    }
}
