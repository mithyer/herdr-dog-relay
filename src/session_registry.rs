//! Relay-side session authority registry for QRM-1.
//!
//! The registry is the pre-forward gate. It stores only bounded authority metadata and never
//! stores Herdr payloads or active tokens in persistent files.

use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, Instant},
};

use crate::{
    error::{RelayError, RelayResult},
    quic_wire::{
        HdqsBinding, HdqsReason, HdqsResponse, QRM_AUTHORITY_BYTES, QRM_MAX_SESSION_NAME_BYTES,
        SessionName,
    },
};

/// Maximum active sessions on one physical QUIC connection.
pub const MAX_SESSION_STREAMS: usize = 64;
/// Bounded token lifetime in seconds.
pub const SESSION_TOKEN_TTL_SECS: u32 = 90;

/// One prepared but not-yet-opened session authority.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedSession {
    /// Canonical session name.
    pub session: SessionName,
    /// Expected fingerprint.
    pub fingerprint: [u8; QRM_AUTHORITY_BYTES],
    /// Core-owned configuration generation.
    pub configuration_generation: u64,
    /// Relay process generation.
    pub relay_generation: u64,
    /// QUIC connection epoch.
    pub connection_epoch: u64,
    /// Opaque token minted for this prepare/open attempt.
    pub token: [u8; QRM_AUTHORITY_BYTES],
    /// Bounded token lifetime.
    pub token_ttl_secs: u32,
    /// Monotonic expiry instant kept in memory only.
    expires_at: Instant,
}

impl fmt::Debug for PreparedSession {
    /// Redacts token and fingerprint bytes from diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSession")
            .field("session", &self.session)
            .field("configuration_generation_present", &true)
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("token_present", &true)
            .field("fingerprint_present", &true)
            .finish()
    }
}
/// One active session stream authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ActiveSession {
    /// Ephemeral connection-local handle.
    pub handle: u16,
    /// Prepared authority retained for the active stream.
    pub prepared: PreparedSession,
    /// Monotonic expiry instant kept in memory only.
    expires_at: Instant,
    /// Whether the one HDQS stream binding has been accepted.
    bound: bool,
}

impl fmt::Debug for ActiveSession {
    /// Redacts token and fingerprint bytes inherited from the prepared authority.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveSession")
            .field("handle", &self.handle)
            .field("prepared", &self.prepared)
            .finish()
    }
}
/// Bounded per-connection session authority registry.
#[derive(Clone)]
pub struct SessionRegistry {
    /// Relay process startup generation.
    relay_generation: u64,
    /// QUIC connection epoch.
    connection_epoch: u64,
    /// Maximum active streams.
    max_sessions: usize,
    /// Next non-zero ephemeral handle.
    next_handle: u16,
    /// Prepared authorities keyed by opaque token.
    prepared: BTreeMap<[u8; QRM_AUTHORITY_BYTES], PreparedSession>,
    /// Active authorities keyed by handle.
    active: BTreeMap<u16, ActiveSession>,
}

impl fmt::Debug for SessionRegistry {
    /// Reports only bounded counts and epochs, never token/fingerprint bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRegistry")
            .field("relay_generation_present", &true)
            .field("connection_epoch_present", &true)
            .field("prepared_count", &self.prepared.len())
            .field("active_count", &self.active.len())
            .finish()
    }
}

impl SessionRegistry {
    /// Creates an empty registry for one QUIC connection.
    ///
    /// # Parameters
    /// * `relay_generation` - Relay process startup epoch.
    /// * `connection_epoch` - Current QUIC connection epoch.
    /// * `max_sessions` - Bounded stream limit.
    ///
    /// # Returns
    /// A registry or a configuration error.
    pub fn new(
        relay_generation: u64,
        connection_epoch: u64,
        max_sessions: usize,
    ) -> RelayResult<Self> {
        if relay_generation == 0
            || connection_epoch == 0
            || max_sessions == 0
            || max_sessions > MAX_SESSION_STREAMS
        {
            return Err(RelayError::InvalidConfiguration {
                field: "limits.max_sessions_per_connection",
                reason: "QRM session registry bounds are invalid",
            });
        }
        Ok(Self {
            relay_generation,
            connection_epoch,
            max_sessions,
            next_handle: 1,
            prepared: BTreeMap::new(),
            active: BTreeMap::new(),
        })
    }

    /// Mints one prepared session authority without opening a Unix socket.
    ///
    /// # Parameters
    /// * `session` - Empty/default/named session input.
    /// * `fingerprint` - Session identity expected by Core.
    /// * `configuration_generation` - Persistent Core/Profile generation.
    /// * `token` - Fresh CSPRNG token supplied by the process owner.
    ///
    /// # Returns
    /// A prepared authority or a redacted validation error.
    // TEST:relay/src/session_registry.rs[tests::prepare_mints_bounded_authority]
    pub fn prepare(
        &mut self,
        session: &str,
        fingerprint: [u8; QRM_AUTHORITY_BYTES],
        configuration_generation: u64,
        token: [u8; QRM_AUTHORITY_BYTES],
    ) -> RelayResult<PreparedSession> {
        self.prepare_at(
            Instant::now(),
            session,
            fingerprint,
            configuration_generation,
            token,
        )
    }

    /// Mints one prepared authority at an injected monotonic instant.
    ///
    /// # Parameters
    /// * `now` - Monotonic clock value used for deterministic expiry tests.
    /// * `session` - Empty/default/named session input.
    /// * `fingerprint` - Session identity expected by Core.
    /// * `configuration_generation` - Persistent Core/Profile generation.
    /// * `token` - Fresh CSPRNG token supplied by the process owner.
    ///
    /// # Returns
    /// A prepared authority or a redacted validation error.
    pub fn prepare_at(
        &mut self,
        now: Instant,
        session: &str,
        fingerprint: [u8; QRM_AUTHORITY_BYTES],
        configuration_generation: u64,
        token: [u8; QRM_AUTHORITY_BYTES],
    ) -> RelayResult<PreparedSession> {
        if self.active.len() + self.prepared.len() >= self.max_sessions {
            return Err(RelayError::ResourceLimit);
        }
        if configuration_generation == 0 || token == [0; QRM_AUTHORITY_BYTES] {
            return Err(RelayError::SessionAuthority);
        }
        let session = SessionName::new(session).map_err(|_| RelayError::SessionAuthority)?;
        if session.as_str().len() > QRM_MAX_SESSION_NAME_BYTES {
            return Err(RelayError::SessionAuthority);
        }
        let prepared = PreparedSession {
            session,
            fingerprint,
            configuration_generation,
            relay_generation: self.relay_generation,
            connection_epoch: self.connection_epoch,
            token,
            token_ttl_secs: SESSION_TOKEN_TTL_SECS,
            expires_at: now + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS)),
        };
        self.prepared.insert(token, prepared.clone());
        Ok(prepared)
    }

    /// Consumes a prepared authority and assigns one non-zero session handle.
    ///
    /// # Parameters
    /// * `binding` - HDQS authority submitted by Core.
    ///
    /// # Returns
    /// A fixed accepted response and active registry entry, or a rejection response.
    // TEST:relay/src/session_registry.rs[tests::binding_requires_exact_authority]
    pub fn open(&mut self, binding: &HdqsBinding) -> (HdqsResponse, Option<ActiveSession>) {
        self.open_at(Instant::now(), binding)
    }

    /// Opens one binding using an injected monotonic instant.
    pub fn open_at(
        &mut self,
        now: Instant,
        binding: &HdqsBinding,
    ) -> (HdqsResponse, Option<ActiveSession>) {
        let Some(prepared) = self.prepared.remove(&binding.token) else {
            return (
                HdqsResponse::rejected(HdqsReason::TokenMismatch, self.connection_epoch),
                None,
            );
        };
        if now >= prepared.expires_at {
            return (
                HdqsResponse::rejected(HdqsReason::TokenMismatch, self.connection_epoch),
                None,
            );
        }
        if self
            .active
            .values()
            .any(|active| active.prepared.session == binding.session)
        {
            return (
                HdqsResponse::rejected(HdqsReason::SessionAlreadyOpen, self.connection_epoch),
                None,
            );
        }
        if prepared.session.as_str() != binding.session.as_str()
            || prepared.fingerprint != binding.fingerprint
            || prepared.configuration_generation != binding.configuration_generation
            || prepared.relay_generation != binding.relay_generation
            || prepared.connection_epoch != binding.connection_epoch
        {
            return (
                HdqsResponse::rejected(HdqsReason::GenerationMismatch, self.connection_epoch),
                None,
            );
        }
        let Some(handle) = self.allocate_handle() else {
            return (
                HdqsResponse::rejected(HdqsReason::CapacityExhausted, self.connection_epoch),
                None,
            );
        };
        let expires_at = now + Duration::from_secs(u64::from(prepared.token_ttl_secs));
        let active = ActiveSession {
            handle,
            prepared,
            expires_at,
            bound: false,
        };
        self.active.insert(handle, active.clone());
        (
            HdqsResponse::accepted(handle, self.connection_epoch),
            Some(active),
        )
    }

    /// Opens one prepared session from a control-plane request and allocates its handle.
    ///
    /// # Parameters
    /// * `request` - Decoded SESSION_OPEN request.
    ///
    /// # Returns
    /// An accepted/rejected fixed response and active authority.
    pub fn open_request(
        &mut self,
        request: &crate::quic_wire::SessionOpenRequest,
    ) -> (HdqsResponse, Option<ActiveSession>) {
        let Some(prepared) = self.prepared.get(&request.token).cloned() else {
            return (
                HdqsResponse::rejected(HdqsReason::TokenMismatch, self.connection_epoch),
                None,
            );
        };
        if prepared.session != request.session
            || prepared.fingerprint != request.fingerprint
            || prepared.configuration_generation != request.configuration_generation
            || prepared.relay_generation != request.relay_generation
            || prepared.connection_epoch != request.connection_epoch
        {
            // Any SESSION_OPEN attempt that found the token must consume it, including a
            // mismatched authority attempt; a caller cannot repair and replay the same token.
            self.prepared.remove(&request.token);
            return (
                HdqsResponse::rejected(HdqsReason::GenerationMismatch, self.connection_epoch),
                None,
            );
        }
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            session: prepared.session,
            fingerprint: prepared.fingerprint,
            token: prepared.token,
        };
        self.open(&binding)
    }

    /// Validates an already active HDQS stream authority without consuming it.
    ///
    /// # Parameters
    /// * `binding` - Exact binding preface received on the session stream.
    ///
    /// # Returns
    /// An accepted/rejected fixed response.
    pub fn accept_active(&mut self, binding: &HdqsBinding) -> HdqsResponse {
        let Some(active) = self.active.get_mut(&binding.session_handle) else {
            return HdqsResponse::rejected(HdqsReason::SessionNotFound, self.connection_epoch);
        };
        if active.bound {
            return HdqsResponse::rejected(HdqsReason::SessionAlreadyOpen, self.connection_epoch);
        }
        if active.prepared.session != binding.session
            || active.prepared.fingerprint != binding.fingerprint
            || active.prepared.configuration_generation != binding.configuration_generation
            || active.prepared.relay_generation != binding.relay_generation
            || active.prepared.connection_epoch != binding.connection_epoch
            || active.prepared.token != binding.token
            || Instant::now() >= active.expires_at
        {
            return HdqsResponse::rejected(HdqsReason::GenerationMismatch, self.connection_epoch);
        }
        active.bound = true;
        HdqsResponse::accepted(active.handle, self.connection_epoch)
    }

    /// Remove one active authority only when every binding field matches.
    ///
    /// This operation is used before sending a rejection so a concurrent or forged handle cannot
    /// revoke another session's authority.
    pub fn close_exact(&mut self, binding: &HdqsBinding) -> bool {
        let Some(active) = self.active.get(&binding.session_handle) else {
            return false;
        };
        if active.prepared.session != binding.session
            || active.prepared.fingerprint != binding.fingerprint
            || active.prepared.configuration_generation != binding.configuration_generation
            || active.prepared.relay_generation != binding.relay_generation
            || active.prepared.connection_epoch != binding.connection_epoch
            || active.prepared.token != binding.token
        {
            return false;
        }
        self.active.remove(&binding.session_handle).is_some()
    }

    ///
    /// # Parameters
    /// * `handle` - Connection-local session handle.
    ///
    /// # Returns
    /// `true` when one active stream authority was removed.
    pub fn close(&mut self, handle: u16) -> bool {
        self.active.remove(&handle).is_some()
    }

    /// Returns whether one exact active binding is currently bound and unexpired.
    pub fn active_bound_exact(&self, binding: &HdqsBinding) -> bool {
        self.active
            .get(&binding.session_handle)
            .is_some_and(|active| {
                active.bound
                    && active.prepared.session == binding.session
                    && active.prepared.fingerprint == binding.fingerprint
                    && active.prepared.configuration_generation == binding.configuration_generation
                    && active.prepared.relay_generation == binding.relay_generation
                    && active.prepared.connection_epoch == binding.connection_epoch
                    && active.prepared.token == binding.token
                    && Instant::now() < active.expires_at
            })
    }

    /// Remove one exact unbound authority after a rejected stream bind.
    ///
    /// The field-by-field check prevents an invalid caller from revoking a sibling session that
    /// happens to reuse the same connection-local handle.
    pub fn close_unbound_if_exact(&mut self, binding: &HdqsBinding) -> bool {
        let Some(active) = self.active.get(&binding.session_handle) else {
            return false;
        };
        if active.bound
            || active.prepared.session != binding.session
            || active.prepared.fingerprint != binding.fingerprint
            || active.prepared.configuration_generation != binding.configuration_generation
            || active.prepared.relay_generation != binding.relay_generation
            || active.prepared.connection_epoch != binding.connection_epoch
            || active.prepared.token != binding.token
        {
            return false;
        }
        self.active.remove(&binding.session_handle).is_some()
    }

    /// Returns the current QUIC connection epoch.
    pub const fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }

    /// Clears all session authority after connection loss.
    pub fn invalidate_connection(&mut self) {
        self.prepared.clear();
        self.active.clear();
    }

    /// Remove expired prepared authorities before a new SESSION_PREPARE admission.
    ///
    /// # Parameters
    /// * `now` - Monotonic instant used for expiry checks.
    ///
    /// # Returns
    /// The number of prepared authorities removed.
    pub fn reap_expired_prepared(&mut self, now: Instant) -> usize {
        let before = self.prepared.len();
        self.prepared
            .retain(|_, prepared| now < prepared.expires_at);
        before - self.prepared.len()
    }

    /// Remove expired active authorities and return their exact handles for bridge cancellation.
    ///
    /// # Parameters
    /// * `now` - Monotonic instant used for expiry checks.
    ///
    /// # Returns
    /// Handles whose token/lease expired during this sweep.
    pub fn reap_expired_handles(&mut self, now: Instant) -> Vec<u16> {
        self.reap_expired_prepared(now);
        let handles: Vec<u16> = self
            .active
            .iter()
            .filter_map(|(handle, active)| (now >= active.expires_at).then_some(*handle))
            .collect();
        for handle in &handles {
            self.active.remove(handle);
        }
        handles
    }

    /// Returns whether one active token is still valid at the supplied instant.
    ///
    /// # Parameters
    /// * `handle` - Connection-local active session handle.
    /// * `token` - Exact opaque token presented by the caller.
    /// * `now` - Monotonic instant used for the check.
    ///
    /// # Returns
    /// `true` only while the exact active authority remains within its TTL.
    pub fn active_is_valid_at(
        &self,
        handle: u16,
        token: &[u8; QRM_AUTHORITY_BYTES],
        now: Instant,
    ) -> bool {
        self.active
            .get(&handle)
            .is_some_and(|active| active.prepared.token == *token && now < active.expires_at)
    }

    /// Renews one active session token when the exact authority remains valid.
    ///
    /// # Parameters
    /// * `handle` - Connection-local handle.
    /// * `token` - Exact active token.
    /// * `now` - Monotonic instant used for renewal.
    ///
    /// # Returns
    /// `true` when the token was active and its TTL was extended.
    pub fn renew(&mut self, handle: u16, token: &[u8; QRM_AUTHORITY_BYTES], now: Instant) -> bool {
        let Some(active) = self.active.get_mut(&handle) else {
            return false;
        };
        if active.prepared.token != *token || now >= active.expires_at {
            return false;
        }
        active.expires_at = now + Duration::from_secs(u64::from(active.prepared.token_ttl_secs));
        true
    }

    // TEST:relay/src/session_registry.rs[tests::renew_batch_rejects_stale_atomically]
    /// Renews a complete heartbeat batch atomically when every authority is valid.
    ///
    /// # Parameters
    /// * `entries` - Exact handle/token pairs claimed by one Core heartbeat.
    /// * `now` - Monotonic instant used for validation and renewal.
    ///
    /// # Returns
    /// `true` when every entry was active and all TTLs were extended; otherwise no entry changes.
    pub fn renew_batch(
        &mut self,
        entries: &[(u16, [u8; QRM_AUTHORITY_BYTES])],
        now: Instant,
    ) -> bool {
        if entries.iter().any(|(handle, token)| {
            self.active
                .get(handle)
                .is_none_or(|active| active.prepared.token != *token || now >= active.expires_at)
        }) {
            return false;
        }
        for (handle, token) in entries {
            let _ = self.renew(*handle, token, now);
        }
        true
    }

    /// Returns the number of active session streams.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Returns an active authority by handle.
    pub fn active(&self, handle: u16) -> Option<&ActiveSession> {
        self.active.get(&handle)
    }

    /// Allocates a non-zero handle that is not currently active.
    fn allocate_handle(&mut self) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let handle = self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1).max(1);
            if handle != 0 && !self.active.contains_key(&handle) {
                return Some(handle);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> SessionRegistry {
        SessionRegistry::new(1, 2, 3).expect("registry")
    }

    fn prepared(registry: &mut SessionRegistry) -> PreparedSession {
        registry
            .prepare("work", [3; 32], 4, [5; 32])
            .expect("prepare")
    }

    // TEST:relay/src/session_registry.rs[tests::prepare_mints_bounded_authority]
    #[test]
    fn prepare_mints_bounded_authority() {
        let mut registry = registry();
        let prepared = prepared(&mut registry);
        assert_eq!(prepared.token_ttl_secs, SESSION_TOKEN_TTL_SECS);
        assert_eq!(prepared.session.as_str(), "work");
    }

    // TEST:relay/src/session_registry.rs[tests::binding_requires_exact_authority]
    #[test]
    fn binding_requires_exact_authority() {
        let mut registry = registry();
        let prepared = prepared(&mut registry);
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            session: prepared.session.clone(),
            fingerprint: prepared.fingerprint,
            token: prepared.token,
        };
        let (response, active) = registry.open(&binding);
        assert_eq!(response.kind as u8, 2);
        assert_eq!(active.expect("active").handle, 1);
    }

    // TEST:relay/src/session_registry.rs[tests::session_open_mismatch_consumes_token]
    #[test]
    fn session_open_mismatch_consumes_token() {
        let mut registry = registry();
        let prepared = prepared(&mut registry);
        let mismatched = crate::quic_wire::SessionOpenRequest {
            session: prepared.session.clone(),
            fingerprint: [4; 32],
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            token: prepared.token,
        };
        let (response, active) = registry.open_request(&mismatched);
        assert_eq!(response.reason, HdqsReason::GenerationMismatch);
        assert!(active.is_none());
        let retry = crate::quic_wire::SessionOpenRequest {
            fingerprint: prepared.fingerprint,
            ..mismatched
        };
        let (response, active) = registry.open_request(&retry);
        assert_eq!(response.reason, HdqsReason::TokenMismatch);
        assert!(active.is_none());
    }

    // TEST:relay/src/session_registry.rs[tests::rejected_binding_cannot_close_sibling]
    #[test]
    fn rejected_binding_cannot_close_sibling() {
        let mut registry = registry();
        let first = prepared(&mut registry);
        let first_binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: first.configuration_generation,
            relay_generation: first.relay_generation,
            connection_epoch: first.connection_epoch,
            session: first.session.clone(),
            fingerprint: first.fingerprint,
            token: first.token,
        };
        let (_, first_active) = registry.open(&first_binding);
        let first_active = first_active.expect("first active");
        let second = registry
            .prepare("other", [6; 32], 4, [7; 32])
            .expect("second prepare");
        let second_binding = HdqsBinding {
            session_handle: 2,
            configuration_generation: second.configuration_generation,
            relay_generation: second.relay_generation,
            connection_epoch: second.connection_epoch,
            session: second.session,
            fingerprint: second.fingerprint,
            token: second.token,
        };
        let (_, second_active) = registry.open(&second_binding);
        let second_active = second_active.expect("second active");
        let sibling_attempt = HdqsBinding {
            session_handle: first_active.handle,
            session: second_active.prepared.session.clone(),
            fingerprint: second_active.prepared.fingerprint,
            configuration_generation: second_active.prepared.configuration_generation,
            relay_generation: second_active.prepared.relay_generation,
            connection_epoch: second_active.prepared.connection_epoch,
            token: second_active.prepared.token,
        };
        assert!(!registry.close_unbound_if_exact(&sibling_attempt));
        assert!(registry.active(first_active.handle).is_some());
        assert!(registry.close_unbound_if_exact(&first_binding));
        assert!(registry.active(second_active.handle).is_some());
    }

    // TEST:relay/src/session_registry.rs[tests::session_ttl_is_enforced]
    #[test]
    fn session_ttl_is_enforced() {
        let mut registry = registry();
        let now = Instant::now();
        let prepared = registry
            .prepare_at(now, "work", [3; 32], 4, [5; 32])
            .expect("prepare");
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            session: prepared.session,
            fingerprint: prepared.fingerprint,
            token: prepared.token,
        };
        let (response, active) = registry.open_at(
            now + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS) + 1),
            &binding,
        );
        assert_eq!(response.reason, HdqsReason::TokenMismatch);
        assert!(active.is_none());
    }

    // TEST:relay/src/session_registry.rs[tests::heartbeat_renews_active_token]
    #[test]
    fn heartbeat_renews_active_token() {
        let mut registry = registry();
        let now = Instant::now();
        let prepared = registry
            .prepare_at(now, "work", [3; 32], 4, [5; 32])
            .expect("prepare");
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            session: prepared.session,
            fingerprint: prepared.fingerprint,
            token: prepared.token,
        };
        let (_, active) = registry.open_at(now, &binding);
        let active = active.expect("active");
        let before_expiry = now + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS) - 1);
        assert!(registry.active_is_valid_at(active.handle, &prepared.token, before_expiry));
        assert!(registry.renew(active.handle, &prepared.token, before_expiry));
        assert!(registry.active_is_valid_at(
            active.handle,
            &prepared.token,
            before_expiry + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS - 1))
        ));
    }

    // TEST:relay/src/session_registry.rs[tests::renew_batch_rejects_stale_atomically]
    #[test]
    fn renew_batch_rejects_stale_atomically() {
        let mut registry = SessionRegistry::new(1, 2, 3).expect("registry");
        let now = Instant::now();
        let first = registry
            .prepare_at(now, "first", [1; 32], 1, [2; 32])
            .expect("first prepare");
        let second = registry
            .prepare_at(now, "second", [3; 32], 1, [4; 32])
            .expect("second prepare");
        let first_binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: first.configuration_generation,
            relay_generation: first.relay_generation,
            connection_epoch: first.connection_epoch,
            session: first.session,
            fingerprint: first.fingerprint,
            token: first.token,
        };
        let second_binding = HdqsBinding {
            session_handle: 2,
            configuration_generation: second.configuration_generation,
            relay_generation: second.relay_generation,
            connection_epoch: second.connection_epoch,
            session: second.session,
            fingerprint: second.fingerprint,
            token: second.token,
        };
        let (_, first_active) = registry.open_at(now, &first_binding);
        let (_, second_active) = registry.open_at(now, &second_binding);
        let first_handle = first_active.expect("first active").handle;
        let second_handle = second_active.expect("second active").handle;
        let expires = now + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS) - 1);
        assert!(!registry.renew_batch(
            &[(first_handle, [2; 32]), (second_handle, [0; 32])],
            expires
        ));
        assert!(registry.active_is_valid_at(first_handle, &[2; 32], expires));
        assert!(registry.active_is_valid_at(second_handle, &[4; 32], expires));
        let after_original_expiry =
            now + Duration::from_secs(u64::from(SESSION_TOKEN_TTL_SECS) + 1);
        assert!(!registry.active_is_valid_at(first_handle, &[2; 32], after_original_expiry));
        assert!(!registry.active_is_valid_at(second_handle, &[4; 32], after_original_expiry));
    }

    // TEST:relay/src/session_registry.rs[tests::duplicate_session_is_rejected]
    #[test]
    fn duplicate_session_is_rejected() {
        let mut registry = registry();
        let first = prepared(&mut registry);
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: first.configuration_generation,
            relay_generation: first.relay_generation,
            connection_epoch: first.connection_epoch,
            session: first.session.clone(),
            fingerprint: first.fingerprint,
            token: first.token,
        };
        assert!(registry.open(&binding).1.is_some());
        let second = registry
            .prepare("work", [3; 32], 4, [6; 32])
            .expect("second prepare");
        let duplicate = HdqsBinding {
            session_handle: 2,
            configuration_generation: second.configuration_generation,
            relay_generation: second.relay_generation,
            connection_epoch: second.connection_epoch,
            session: second.session,
            fingerprint: second.fingerprint,
            token: second.token,
        };
        let (response, active) = registry.open(&duplicate);
        assert_eq!(response.reason, HdqsReason::SessionAlreadyOpen);
        assert!(active.is_none());
    }

    // TEST:relay/src/session_registry.rs[tests::three_sessions_are_isolated]
    #[test]
    fn three_sessions_are_isolated() {
        let mut registry = SessionRegistry::new(1, 2, 3).expect("registry");
        let mut handles = Vec::new();
        for (index, name) in ["default", "work", "review"].into_iter().enumerate() {
            let token = [index as u8 + 1; 32];
            let prepared = registry
                .prepare(name, [index as u8 + 3; 32], 1, token)
                .expect("prepare");
            let binding = HdqsBinding {
                session_handle: index as u16 + 1,
                configuration_generation: prepared.configuration_generation,
                relay_generation: prepared.relay_generation,
                connection_epoch: prepared.connection_epoch,
                session: prepared.session,
                fingerprint: prepared.fingerprint,
                token: prepared.token,
            };
            let (response, active) = registry.open(&binding);
            assert_eq!(response.kind as u8, 2);
            handles.push(active.expect("active").handle);
        }
        assert_eq!(registry.active_count(), 3);
        assert!(handles.windows(2).all(|window| window[0] != window[1]));
        assert!(registry.close(handles[1]));
        assert!(registry.active(handles[0]).is_some());
        assert!(registry.active(handles[2]).is_some());
    }

    #[test]
    fn prepared_capacity_is_bounded() {
        let mut registry = SessionRegistry::new(1, 2, 2).expect("registry");
        registry.prepare("one", [1; 32], 1, [1; 32]).expect("first");
        registry
            .prepare("two", [2; 32], 1, [2; 32])
            .expect("second");
        assert_eq!(
            registry
                .prepare("three", [3; 32], 1, [3; 32])
                .unwrap_err()
                .to_string(),
            "relay resource limit reached"
        );
    }

    #[test]
    fn wrong_token_is_rejected_before_forward() {
        let mut registry = registry();
        let prepared = prepared(&mut registry);
        let binding = HdqsBinding {
            session_handle: 1,
            configuration_generation: prepared.configuration_generation,
            relay_generation: prepared.relay_generation,
            connection_epoch: prepared.connection_epoch,
            session: prepared.session,
            fingerprint: prepared.fingerprint,
            token: [9; 32],
        };
        let (response, active) = registry.open(&binding);
        assert_eq!(response.reason, HdqsReason::TokenMismatch);
        assert!(active.is_none());
        assert_eq!(registry.active_count(), 0);
    }
}
