//! NIP-FI final-authority orchestration — relay-private module.
//!
//! ## Security boundary
//!
//! [`SealedRequestContext`] has private fields and is only constructible via
//! [`seal_context`], which is also private to this module. External crates
//! cannot name or call either path; the Rust module system is the enforcer.
//!
//! ## Architecture
//!
//! ```text
//! buzz-auth  ─ closed vocabularies, VerifiedAssertion, FederatedAssertionVerifier
//! buzz-db    ─ raw SQL helpers (pool, store primitives)
//! buzz-relay/src/nip_fi  ─ THIS MODULE
//!   context.rs   SealedRequestContext (private fields), seal_context()
//!   admission.rs commit_admission_in_tx(), authorize_protected_use_in_tx()
//! ```
//!
//! No public buzz-db API mints PreparedAuthorization/CommittedAuthorization/
//! AuthorizedUse from caller-selected scalars.  The admission SQL lives here.
//!
//! ## Handler integration (Design C — one READ COMMITTED transaction)
//!
//! Single entry point on [`NipFiVerify`]:
//!
//! 1. [`NipFiVerify::verify_compact_jws`] — called once at WebSocket upgrade
//!    time.  Extracts and verifies the compact JWS from the
//!    `Nostr-Federated-Identity` header; the result is stored on the connection
//!    state and combined with the later NIP-42 AUTH proof at event time.
//!
//! 2. [`NipFiVerify::commit_kind9_atomic`] — called from `ingest_event_inner`
//!    for `KIND_STREAM_MESSAGE` when the connection carried a NIP-FI assertion.
//!    Opens ONE READ COMMITTED transaction and, in order:
//!      a. `assert_community_write_allowed` — shared deletion advisory lock
//!      b. `acquire_nip_fi_writer_lock` — exclusive per-community NIP-FI lock
//!      c. Final admission (enrollment, replay claim, receipts, epoch/fence,
//!         protected_object_authority)  [commit_admission_in_tx]
//!      d. Immediate re-fence / protected-use revalidation  [authorize_protected_use_in_tx]
//!      e. Event insert  [Db::insert_event_with_thread_metadata_in_tx]
//!    then commits once.  Any error rolls back all authority mutations and the
//!    event insert together (satisfies FI-INV-09 all-or-none and
//!    FI-TRACE-FINAL-DENIAL-NO-MUTATION).
//!
//! A `None` `AppState::nip_fi` means NIP-FI is disabled; kind-9 events are
//! then admitted by the baseline NIP-29 membership check alone.

mod admission;
mod context;

use buzz_auth::nip_fi::{
    AdmissionError, BindingProposal, BindingProvenance, FederatedAssertionVerifier,
    IssuerKeySource, OperationIntent, ProofTransport, ProtectedObjectKind, RouteCapability,
    VerifiedAssertion, VerifierError,
};
use buzz_core::{CommunityId, StoredEvent};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// All per-request parameters for a NIP-FI kind-9 admission call.
///
/// Grouped to avoid the too-many-arguments limit on [`NipFiVerify::commit_kind9_atomic`]
/// and [`commit_kind9_inner`].
///
/// The admission `operation_id` is **not** a field here — it is derived
/// deterministically inside `commit_kind9_inner` from
/// `(community_id, proof_event_id, event.id)` via UUID v5.  Callers never
/// allocate or pass it.
pub(crate) struct Kind9Params {
    pub(crate) community_id: Uuid,
    pub(crate) channel_id: Uuid,
    pub(crate) actor: nostr::PublicKey,
    pub(crate) conn_id: Uuid,
    pub(crate) challenge: String,
    pub(crate) relay_url: String,
    pub(crate) proof_event_id: [u8; 32],
    pub(crate) proof_expires_at: DateTime<Utc>,
    pub(crate) transport: ProofTransport,
    pub(crate) verified_assertion: VerifiedAssertion,
    pub(crate) proposal: BindingProposal,
    pub(crate) event: nostr::Event,
    pub(crate) thread_meta: Option<crate::handlers::ingest::ThreadMetadataOwned>,
}

/// Relay-local verifier trait.  Abstracts over the generic
/// `FederatedAssertionVerifier<S>` so `AppState` can hold `Arc<dyn NipFiVerify>`
/// without exposing the `IssuerKeySource` type parameter.
///
/// Only `nip_fi` module code implements this trait.
#[async_trait::async_trait]
pub(crate) trait NipFiVerify: Send + Sync {
    /// Verify a compact JWS token from the `Nostr-Federated-Identity` header.
    ///
    /// Called once at WebSocket upgrade time.  The token is the `Bearer` value
    /// from the `Nostr-Federated-Identity` HTTP header.  Returns the sealed
    /// `VerifiedAssertion` for storage on the connection state.
    ///
    /// Fails closed: any verification error rejects the assertion (the
    /// connection may still proceed as plain NIP-42, but NIP-FI admission
    /// will be unavailable for events on this connection).
    fn verify_compact_jws(&self, compact_jws: &str) -> Result<VerifiedAssertion, VerifierError>;

    /// Execute the full NIP-FI admission + protected-use re-fence + event
    /// insert in ONE atomic READ COMMITTED transaction (Design C).
    ///
    /// Steps, all inside a single `BEGIN … COMMIT`:
    ///   1. `assert_community_write_allowed` — shared deletion advisory lock
    ///   2. `acquire_nip_fi_writer_lock` — exclusive per-community NIP-FI lock
    ///   3. `SELECT transaction_timestamp()` as `db_now`
    ///   4. `commit_admission_in_tx` — enrollment, replay claim, receipts,
    ///      epoch/fence, `protected_object_authority` upsert
    ///   5. `authorize_protected_use_in_tx` — re-read every committed witness,
    ///      advance the epoch/fence one final time
    ///   6. `insert_event_with_thread_metadata_in_tx` — event row insert
    ///   7. `COMMIT`
    ///
    /// Any error at any step rolls back all authority mutations AND the event
    /// insert together — zero orphaned enrollment/replay/receipt/fence rows.
    ///
    /// Returns `(StoredEvent, was_inserted)` on success, exactly matching the
    /// contract of the non-NIP-FI event insert path so callers can treat them
    /// identically.
    async fn commit_kind9_atomic(
        &self,
        params: Kind9Params,
    ) -> Result<(StoredEvent, bool), AdmissionError>;
}

/// Concrete implementation of [`NipFiVerify`] that wraps the production
/// `FederatedAssertionVerifier<S>` and a `buzz_db::Db` handle.
pub(crate) struct NipFiVerifierImpl<S: IssuerKeySource + Sync + Send + 'static> {
    db: Arc<buzz_db::Db>,
    verifier: Arc<FederatedAssertionVerifier<S>>,
}

impl<S: IssuerKeySource + Sync + Send + 'static> NipFiVerifierImpl<S> {
    /// Create a new verifier wrapper.
    pub(crate) fn new(db: Arc<buzz_db::Db>, verifier: FederatedAssertionVerifier<S>) -> Self {
        Self {
            db,
            verifier: Arc::new(verifier),
        }
    }
}

#[async_trait::async_trait]
impl<S: IssuerKeySource + Sync + Send + 'static> NipFiVerify for NipFiVerifierImpl<S> {
    fn verify_compact_jws(&self, compact_jws: &str) -> Result<VerifiedAssertion, VerifierError> {
        self.verifier.verify(compact_jws)
    }

    async fn commit_kind9_atomic(
        &self,
        params: Kind9Params,
    ) -> Result<(StoredEvent, bool), AdmissionError> {
        // Revalidate the compact JWS once, before the transaction opens.
        // This keeps the network round-trip out of the transaction.
        let fresh_assertion = admission::revalidate_assertion(
            &*self.verifier,
            &params.verified_assertion,
            chrono::Utc::now(),
        )?;

        commit_kind9_inner(&self.db, params, fresh_assertion).await
    }
}

/// Domain-separated UUID-v5 namespace for admission operation IDs.
///
/// SHA-256("buzz.nip-fi.admission-op.v1"), truncated to 16 bytes.
const NS_ADMISSION_OP: [u8; 16] = {
    // SHA-256("buzz.nip-fi.admission-op.v1") first 16 bytes (big-endian):
    //   echo -n "buzz.nip-fi.admission-op.v1" | sha256sum
    //   → 1c4b7f0a e2d93518 85c62f4b 3a910cd7 ...
    [
        0x1c, 0x4b, 0x7f, 0x0a, 0xe2, 0xd9, 0x35, 0x18,
        0x85, 0xc6, 0x2f, 0x4b, 0x3a, 0x91, 0x0c, 0xd7,
    ]
};

/// Derive a deterministic admission operation ID from `(community_id,
/// proof_event_id, signed_event_id)` via UUID v5 (SHA-1 namespaced).
///
/// Domain-separating the three binding dimensions prevents collisions across
/// communities, proof reuses, and signed events.  The full 32-byte signed
/// event ID is included so replayed proofs on different messages produce
/// distinct operation IDs.
fn deterministic_admission_op_id(
    community_id: Uuid,
    proof_event_id: &[u8; 32],
    signed_event_id: &[u8; 32],
) -> Uuid {
    let mut payload = Vec::with_capacity(16 + 32 + 32);
    payload.extend_from_slice(community_id.as_bytes());
    payload.extend_from_slice(proof_event_id);
    payload.extend_from_slice(signed_event_id);
    Uuid::new_v5(&Uuid::from_bytes(NS_ADMISSION_OP), &payload)
}

/// Shared transaction body for Design C admission.
///
/// Called by both [`NipFiVerifierImpl`] (production, after JWS revalidation)
/// and the test orchestrator (after the JWS check is bypassed).  Every step —
/// community write assertion, NIP-FI writer lock, final admission, re-fence,
/// event insert, commit — executes inside one READ COMMITTED transaction.
async fn commit_kind9_inner(
    db: &buzz_db::Db,
    params: Kind9Params,
    fresh_assertion: VerifiedAssertion,
) -> Result<(StoredEvent, bool), AdmissionError> {
    use sha2::{Digest, Sha256};

    let Kind9Params {
        community_id,
        channel_id,
        actor,
        conn_id,
        challenge,
        relay_url,
        proof_event_id,
        proof_expires_at,
        transport,
        verified_assertion,
        proposal,
        event,
        thread_meta,
    } = params;

    // Derive the admission operation ID deterministically from the three binding
    // dimensions — community, proof event, and signed message event.  This
    // makes the operation ID idempotent: the same (community, proof, event)
    // triple always produces the same operation ID, enabling the read-time
    // exact-replay protocol in commit_admission_body.
    let signed_event_id: [u8; 32] = event.id.to_bytes();
    let event_created_at: DateTime<Utc> = {
        use std::time::{Duration, UNIX_EPOCH};
        let ts = event.created_at.as_secs();
        DateTime::from(UNIX_EPOCH + Duration::from_secs(ts))
    };
    let operation_id = deterministic_admission_op_id(community_id, &proof_event_id, &signed_event_id);

    // SHA-256 of the 16-byte canonical UUID — identical to PostgreSQL's
    // sha256(uuid_send(c.id)).
    let object_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(channel_id.as_bytes());
        h.finalize().into()
    };

    let community_id_typed = CommunityId::from_uuid(community_id);

    let ctx = context::SealedRequestContext::seal_inline(
        transport,
        proof_event_id,
        proof_expires_at,
        actor,
        community_id,
        RouteCapability::MessagesWrite,
        ProtectedObjectKind::Channel,
        OperationIntent::Write,
        object_key,
        None, // object_version
        conn_id,
        challenge.clone(),
        relay_url.clone(),
        verified_assertion,
        operation_id,
        signed_event_id,
        event_created_at,
    );

    // Retry loop for transient advisory-lock collisions.
    let mut attempts = 0usize;
    loop {
        attempts += 1;

        // One READ COMMITTED transaction for the combined admission + insert.
        // The community write fence trigger rejects any isolation level other
        // than READ COMMITTED.
        let mut tx = db
            .begin_transaction()
            .await
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;

        let db_now: DateTime<Utc> = match sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut *tx)
            .await
        {
            Ok(t) => t,
            Err(e) => return Err(AdmissionError::Transient(e.to_string())),
        };

        // Step A: community write assertion + NIP-FI writer lock + admission.
        let committed = match admission::commit_admission_in_tx(
            &mut tx,
            db_now,
            &ctx,
            &proposal,
            &fresh_assertion,
        )
        .await
        {
            Ok(c) => c,
            Err(AdmissionError::SerializationRetry)
                if attempts < admission::MAX_SERIALIZATION_RETRIES =>
            {
                tokio::time::sleep(std::time::Duration::from_millis((attempts as u64) * 5)).await;
                continue;
            }
            Err(e) => return Err(e),
        };

        // Step B: protected-use re-fence inside the same tx.
        if let Err(e) = admission::authorize_protected_use_in_tx(
            &mut tx,
            db_now,
            &committed,
            conn_id,
            &challenge,
            &relay_url,
            &proof_event_id,
            transport,
            &actor,
        )
        .await
        {
            if matches!(e, AdmissionError::SerializationRetry)
                && attempts < admission::MAX_SERIALIZATION_RETRIES
            {
                tokio::time::sleep(std::time::Duration::from_millis((attempts as u64) * 5)).await;
                continue;
            }
            return Err(e);
        }

        // Step C: event insert inside the same tx — no separate commit.
        let thread_params = thread_meta.as_ref().map(|m| m.as_params());
        let result = match db
            .insert_event_with_thread_metadata_in_tx(
                &mut tx,
                community_id_typed,
                &event,
                Some(channel_id),
                thread_params,
            )
            .await
        {
            Ok(r) => r,
            Err(buzz_db::DbError::AuthEventRejected) => {
                return Err(AdmissionError::Transient(
                    "AUTH events cannot be stored".into(),
                ));
            }
            Err(e) => return Err(AdmissionError::Transient(e.to_string())),
        };

        // Step D: duplicate-event guard — if the event already exists, the
        // event-precheck in commit_admission_body should have caught it
        // (step 3 in the amended protocol).  If a race produces was_inserted=false
        // here instead, we must NOT commit the authority mutations; roll back
        // and return the duplicate result from a clean read.
        if !result.1 {
            // Explicit rollback: no authority mutations reach disk.
            let _ = tx.rollback().await;
            return Ok(result);
        }

        // Step E: commit — all authority mutations + event insert or nothing.
        match tx
            .commit()
            .await
            .map_err(|e| AdmissionError::Transient(e.to_string()))
        {
            Ok(()) => {
                db.insert_mentions_post_commit(community_id_typed, &event, Some(channel_id))
                    .await;
                return Ok(result);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Build a [`BindingProposal`] from a verified assertion and actor public key.
///
/// The `binding_id` is a freshly generated UUID — used as the candidate
/// binding identifier for new enrollments; existing bindings are resolved from
/// the DB by (issuer, subject) and the candidate UUID is ignored.
///
/// Called by the event handler once both the NIP-FI assertion and the NIP-42
/// proof have been validated, before passing the context to `ingest_event`.
pub(crate) fn make_binding_proposal(
    actor_pubkey: &[u8; 32],
    assertion: &VerifiedAssertion,
) -> BindingProposal {
    let issuer = assertion.identity().issuer();
    let subject = assertion.identity().subject();
    let principal_fingerprint =
        admission::compute_principal_fingerprint(actor_pubkey, issuer, subject);
    let provenance = if assertion.asserted_key().is_some() {
        BindingProvenance::AttestedKey
    } else {
        BindingProvenance::RiskLabelledTofu
    };
    BindingProposal {
        binding_id: uuid::Uuid::new_v4(),
        provenance,
        principal_fingerprint,
        known_version: None,
    }
}

// ── Test orchestrator ─────────────────────────────────────────────────────────
//
// `NipFiTestOrchestrator` delegates to `commit_kind9_inner` — the exact same
// shared body used by `NipFiVerifierImpl` — but skips the JWS revalidation
// step.  This lets PostgreSQL integration tests exercise the production code
// path without a live JWKS endpoint.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Test-only orchestrator that drives `commit_kind9_inner` directly,
    /// bypassing JWS revalidation.  Every transactional step is production code.
    pub(crate) struct NipFiTestOrchestrator {
        pub(crate) db: Arc<buzz_db::Db>,
    }

    impl NipFiTestOrchestrator {
        pub(crate) fn new(db: Arc<buzz_db::Db>) -> Self {
            Self { db }
        }
    }

    #[async_trait::async_trait]
    impl NipFiVerify for NipFiTestOrchestrator {
        fn verify_compact_jws(
            &self,
            _compact_jws: &str,
        ) -> Result<VerifiedAssertion, VerifierError> {
            Err(VerifierError::MalformedToken)
        }

        async fn commit_kind9_atomic(
            &self,
            params: Kind9Params,
        ) -> Result<(StoredEvent, bool), AdmissionError> {
            // JWS revalidation skipped — pass the incoming assertion as both
            // the sealed context assertion and the fresh revalidated assertion.
            let fresh_assertion = params.verified_assertion.clone();
            commit_kind9_inner(&self.db, params, fresh_assertion).await
        }
    }
}
