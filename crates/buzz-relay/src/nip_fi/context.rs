//! Origin-sealed request context for NIP-FI final admission.
//!
//! [`SealedRequestContext`] can only be constructed inside the `nip_fi`
//! module.  External crates cannot name or call the construction path.

use buzz_auth::nip_fi::{
    OperationIntent, ProofTransport, ProtectedObjectKind, RouteCapability, VerifiedAssertion,
};
use chrono::{DateTime, Utc};
use nostr::PublicKey;
use uuid::Uuid;

/// Origin-sealed server-resolved request context, carrying the full
/// [`VerifiedAssertion`] for revalidation inside the final transaction.
///
/// All fields are private; construction is only possible via [`SealedRequestContext::seal_inline`]
/// inside this module.  The `FederatedAssertionVerifier` is not stored here —
/// it is passed into `commit_admission` so revalidation happens inside the
/// transaction boundary.
pub(crate) struct SealedRequestContext {
    /// Nostr-proof transport that bound the actor.
    pub(super) transport: ProofTransport,
    /// Full 32-byte event ID of the NIP-42 AUTH or NIP-98 proof event.
    pub(super) proof_event_id: [u8; 32],
    /// Freshness deadline of the proof.
    pub(super) proof_expires_at: DateTime<Utc>,
    /// Server-resolved 32-byte Nostr public key of the proven actor.
    pub(super) actor: PublicKey,
    /// Community (tenant) UUID.
    pub(super) community_id: Uuid,
    /// Server-resolved canonical route capability.
    pub(super) capability: RouteCapability,
    /// Protected-object kind.
    pub(super) object_kind: ProtectedObjectKind,
    /// Operation intent.
    pub(super) intent: OperationIntent,
    /// Server-resolved 32-byte protected-object key.
    pub(super) object_key: [u8; 32],
    /// Object version / fingerprint witness at the time of the request.
    pub(super) object_version: Option<i64>,
    /// WebSocket connection UUID.
    pub(super) conn_id: Uuid,
    /// NIP-42 challenge string.
    pub(super) challenge: String,
    /// Canonical relay URL.
    pub(super) relay_url: String,
    /// The full verified assertion — carried for revalidation in the final
    /// transaction.  Contains `RevalidationDependencies` with the confidential
    /// compact JWS, key identity, snapshot generation, and hard deadline.
    pub(super) verified_assertion: VerifiedAssertion,
    /// Operation UUID for this request.
    pub(super) operation_id: Uuid,
    /// Full 32-byte Nostr event ID of the signed kind-9 message event.
    /// Used in deterministic operation-ID derivation and request fingerprinting
    /// to bind the operation to this exact signed event.
    pub(super) signed_event_id: [u8; 32],
    /// Creation timestamp of the signed kind-9 message event.
    /// Used in the event duplicate precheck query.
    pub(super) event_created_at: DateTime<Utc>,
}

impl std::fmt::Debug for SealedRequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRequestContext")
            .field("transport", &self.transport)
            .field("conn_id", &self.conn_id)
            .field("community_id", &self.community_id)
            .field("capability", &self.capability)
            .field("object_kind", &self.object_kind)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl SealedRequestContext {
    /// Seal a request context directly from server-resolved coordinates,
    /// bypassing the `AuthService` round-trip that `seal_context` required.
    ///
    /// The ingest handler already verified the NIP-42 AUTH event and resolved
    /// the actor pubkey — this path re-uses that verification rather than
    /// re-running it.  Called only from `NipFiVerifierImpl::commit_kind9_atomic`
    /// inside this module (`buzz_relay::nip_fi`).
    ///
    /// # Visibility
    ///
    /// `pub(super)` restricts construction to the `buzz_relay::nip_fi` orchestrator.
    /// Other `buzz_relay` modules (e.g., `handlers::event`) cannot call this
    /// constructor.  If this were widened to `pub(crate)`, any handler could mint
    /// a `SealedRequestContext` from arbitrary coordinates, bypassing the trusted
    /// auth-handshake path.  The `pub(super)` visibility enforces this wall via
    /// the Rust module system; this docstring is the intra-crate contract.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_inline(
        transport: ProofTransport,
        proof_event_id: [u8; 32],
        proof_expires_at: DateTime<Utc>,
        actor: nostr::PublicKey,
        community_id: Uuid,
        capability: RouteCapability,
        object_kind: ProtectedObjectKind,
        intent: OperationIntent,
        object_key: [u8; 32],
        object_version: Option<i64>,
        conn_id: Uuid,
        challenge: String,
        relay_url: String,
        verified_assertion: VerifiedAssertion,
        operation_id: Uuid,
        signed_event_id: [u8; 32],
        event_created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            transport,
            proof_event_id,
            proof_expires_at,
            actor,
            community_id,
            capability,
            object_kind,
            intent,
            object_key,
            object_version,
            conn_id,
            challenge,
            relay_url,
            verified_assertion,
            operation_id,
            signed_event_id,
            event_created_at,
        }
    }
}

#[cfg(test)]
impl SealedRequestContext {
    /// Build a minimal sealed context for integration tests.
    ///
    /// **Test-only.  Never call in production code.**
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        actor: nostr::PublicKey,
        community_id: Uuid,
        capability: RouteCapability,
        object_kind: ProtectedObjectKind,
        intent: OperationIntent,
        object_key: [u8; 32],
        conn_id: Uuid,
        challenge: &str,
        relay_url: &str,
        proof_event_id: [u8; 32],
        proof_expires_at: DateTime<Utc>,
        verified_assertion: VerifiedAssertion,
        operation_id: Uuid,
    ) -> Self {
        Self {
            transport: ProofTransport::Nip42WebSocket,
            proof_event_id,
            proof_expires_at,
            actor,
            community_id,
            capability,
            object_kind,
            intent,
            object_key,
            object_version: None,
            conn_id,
            challenge: challenge.to_string(),
            relay_url: relay_url.to_string(),
            verified_assertion,
            operation_id,
            signed_event_id: [0u8; 32], // synthetic; not used in pure-Rust test paths
            event_created_at: proof_expires_at, // synthetic; use deadline as placeholder
        }
    }
}
