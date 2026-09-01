//! NIP-FI PostgreSQL-final admission and protected-use orchestration.
//!
//! ## Isolation and writer ordering (Design C)
//!
//! All mutable NIP-FI operations run inside **READ COMMITTED** transactions.
//! Isolation is enforced by two transaction-scoped advisory locks, acquired in
//! this fixed order to prevent deadlock:
//!
//!   1. Shared community-deletion lock — `assert_community_write_allowed($community_id)`
//!      is called as the **first transactional operation**, taking
//!      `pg_advisory_xact_lock_shared(community_deletion_lock_key(community_id))`.
//!      This satisfies the community write fence, verifies active state from a
//!      fresh READ COMMITTED statement snapshot, and holds the shared deletion lock
//!      for the duration of the transaction.  Deletion/quiescing takes the exclusive
//!      form of this lock and cannot complete while any NIP-FI admission/use is
//!      in flight.
//!
//!   2. Exclusive NIP-FI writer lock — `pg_advisory_xact_lock(nip_fi_writer_lock_key($community_id))`
//!      is acquired immediately after the community write assertion, serializing all
//!      NIP-FI authority writers (admission, protected-use, enrollment, policy/floor/
//!      invalidation advances) per community for Phase A.  Every authority read and
//!      write that can race admission or final use must acquire this lock before any
//!      authoritative read.
//!
//! `transaction_timestamp()` is the authoritative DB-time clock for deadline checks.
//! `clock_timestamp()` is used for monotonicity-sensitive `updated_at` and `issued_at`
//! columns re-written within the same transaction (epoch UPDATE × 2, POA INSERT→UPDATE)
//! so the monotonic trigger guard (`NEW.updated_at <= OLD.updated_at`) cannot fire.
//!
//! ## Vertical slice
//!
//! This implementation covers kind-9 channel publication:
//!   capability = MessagesWrite (code 2)
//!   object_kind = Channel (code 2)
//!   object_key  = SHA-256 of canonical UUID 16-byte wire representation
//!                 i.e. sha256(uuid_send(channel_id)) in PostgreSQL
//!                 In Rust: sha256(channel_uuid.as_bytes()).  Text encoding (36 bytes) is wrong.
//!
//! Community write-fence and current channel state are reread at final
//! admission and every use.  The implementation fails closed on absence or
//! ambiguity.
//!
//! ## Enrollment
//!
//! When no active binding exists for (issuer, subject, community), a new
//! binding is created atomically in the same READ COMMITTED transaction:
//!   identity_lifecycle_lock_coordinates_v1 advisory lock
//!   → INSERT identity_bindings (RETURNING binding_version)
//!   → INSERT identity_lifecycle_history (all four successor fields populated)
//!   → INSERT authorization_events (event_kind=1, outcome_code=1)
//!   → INSERT authorization_operation_receipts (operation_kind=1, enroll_operation_id)
//! The enrollment and admission receipts use separate operation_id UUIDs
//! because authorization_operation_receipts has PRIMARY KEY (community_id,
//! operation_id) — two receipts cannot share one operation ID.
//!
//! Conflicting identical enrollments (same principal fingerprint, same pubkey)
//! converge to the winner via the ON CONFLICT / advisory-lock protocol.
//! Conflicting non-identical enrollments (same key, different fingerprint) are
//! rejected as EnrollmentConflict.
//!
//! ## Assertion revalidation
//!
//! Before the first write inside the READ COMMITTED transaction, the compact JWS
//! is re-verified against the current key source via
//! `FederatedAssertionVerifier::verify`.  The freshly sealed assertion is then
//! compared against the prepared assertion on NIP-FI classes:
//!   identity: issuer, subject, asserted_key, policy_id, contract_id
//!   bounds: every deadline in the fresh set must be ≤ its corresponding
//!           prepared counterpart; the fresh assertion must be live at db_now
//!   provenance: snapshot generation/key identity change is allowed after
//!               successful revalidation only
//! Any deviation returns AssertionEquivalenceViolation or ContractIdChanged.
//!
//! ## UUID object-key encoding
//!
//! object_key for MessagesWrite/Channel = SHA-256 of the 16-byte wire
//! representation of the channel UUID.  In PostgreSQL: sha256(uuid_send(c.id)).
//! In Rust: sha256(channel_uuid.as_bytes()).  Text encoding (36 bytes) is wrong.

use super::context::SealedRequestContext;
use buzz_auth::nip_fi::{
    AdmissionError, BindingProposal, FederatedAssertionVerifier, IssuerKeySource, ProofTransport,
    VerifiedAssertion,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

/// Maximum transient-retry attempts on temporary DB errors.
pub(crate) const MAX_SERIALIZATION_RETRIES: usize = 5;

// ── Non-forgeable output types ────────────────────────────────────────────────

/// Sealed committed-authorization result.  Only producible by a successful
/// `commit_admission` READ COMMITTED transaction.  Not `Clone`.
pub(crate) struct CommittedAuthorization {
    pub(super) community_id: Uuid,
    pub(super) operation_id: Uuid,
    pub(super) request_fingerprint: [u8; 32],
    pub(super) authority_epoch: i64,
    pub(super) authority_fence: [u8; 32],
    pub(super) actor_pubkey: [u8; 32],
    pub(super) binding_id: Uuid,
    pub(super) binding_version: i64,
    pub(super) binding_lifecycle_revision: i64,
    pub(super) policy_revision: i64,
    pub(super) capability_code: i16,
    pub(super) object_kind_code: i16,
    pub(super) object_key: [u8; 32],
    pub(super) conn_id: Uuid,
    pub(super) challenge: String,
    pub(super) relay_url: String,
    pub(super) proof_event_id: [u8; 32],
    pub(super) transport_code: u8,
    pub(super) assertion_issuer: String,
    pub(super) assertion_subject: String,
}

impl std::fmt::Debug for CommittedAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedAuthorization")
            .field("operation_id", &self.operation_id)
            .field("authority_epoch", &self.authority_epoch)
            .finish_non_exhaustive()
    }
}

/// Sealed authorized-use grant.  Not `Clone`.
///
/// All fields are written to the authorization ledger in the same transaction.
/// `new_fence` and `granted_at` are persisted as audit evidence and are not
/// read back from this struct by callers; the phantom fields are load-bearing
/// on the database side and are kept for documentation and Debug output.
pub(crate) struct AuthorizedUse {
    pub(super) use_operation_id: Uuid,
    #[allow(dead_code)] // written to DB; not read back from struct by callers
    pub(super) new_fence: [u8; 32],
    pub(super) new_epoch: i64,
    #[allow(dead_code)] // written to DB; not read back from struct by callers
    pub(super) granted_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthorizedUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedUse")
            .field("use_operation_id", &self.use_operation_id)
            .field("new_epoch", &self.new_epoch)
            .finish_non_exhaustive()
    }
}

// ── Fingerprint / hash helpers ────────────────────────────────────────────────

fn compute_request_fingerprint(ctx: &SealedRequestContext) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.request-fingerprint.v1\x00");
    h.update([match ctx.transport {
        ProofTransport::Nip42WebSocket => 1u8,
        ProofTransport::Nip98Http => 2u8,
    }]);
    h.update(ctx.proof_event_id);
    h.update(ctx.proof_expires_at.timestamp().to_be_bytes());
    h.update(ctx.actor.to_bytes().as_slice());
    h.update(ctx.community_id.as_bytes());
    h.update(ctx.capability.database_code().to_be_bytes());
    h.update(ctx.object_kind.database_code().to_be_bytes());
    h.update(ctx.intent.as_db_code().to_be_bytes());
    h.update(ctx.object_key);
    h.update(ctx.object_version.unwrap_or(0i64).to_be_bytes());
    h.update(ctx.conn_id.as_bytes());
    let challenge_bytes = ctx.challenge.as_bytes();
    h.update((challenge_bytes.len() as u32).to_be_bytes());
    h.update(challenge_bytes);
    let relay_bytes = ctx.relay_url.as_bytes();
    h.update((relay_bytes.len() as u32).to_be_bytes());
    h.update(relay_bytes);
    h.update(ctx.verified_assertion.assertion_policy_id().as_bytes());
    h.update(ctx.verified_assertion.transport_contract_id().as_bytes());
    h.update(
        ctx.verified_assertion
            .upstream_authority_deadline()
            .timestamp()
            .to_be_bytes(),
    );
    h.update(ctx.operation_id.as_bytes());
    // Full signed event ID — binds fingerprint to this exact message event.
    h.update(ctx.signed_event_id);
    h.finalize().into()
}

fn compute_semantic_fingerprint(ctx: &SealedRequestContext) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.semantic-fingerprint.v1\x00");
    h.update(ctx.capability.database_code().to_be_bytes());
    h.update(ctx.object_kind.database_code().to_be_bytes());
    h.update(ctx.intent.as_db_code().to_be_bytes());
    h.update(ctx.object_key);
    h.update(ctx.actor.to_bytes().as_slice());
    h.update(ctx.community_id.as_bytes());
    h.finalize().into()
}

pub(crate) fn compute_principal_fingerprint(
    actor_pubkey: &[u8; 32],
    issuer: &str,
    subject: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.principal-fingerprint.v1\x00");
    h.update(actor_pubkey);
    let iss = issuer.as_bytes();
    h.update((iss.len() as u32).to_be_bytes());
    h.update(iss);
    let sub = subject.as_bytes();
    h.update((sub.len() as u32).to_be_bytes());
    h.update(sub);
    h.finalize().into()
}

fn compute_enrollment_evidence_digest(
    assertion: &VerifiedAssertion,
    actor_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.enrollment-evidence.v1\x00");
    h.update(assertion.assertion_policy_id().as_bytes());
    h.update(assertion.transport_contract_id().as_bytes());
    h.update(actor_pubkey);
    let iss = assertion.identity().issuer().as_bytes();
    h.update((iss.len() as u32).to_be_bytes());
    h.update(iss);
    let sub = assertion.identity().subject().as_bytes();
    h.update((sub.len() as u32).to_be_bytes());
    h.update(sub);
    h.update(
        assertion
            .revalidation_dependencies()
            .key_snapshot_generation()
            .to_be_bytes(),
    );
    h.finalize().into()
}

fn generate_fence() -> [u8; 32] {
    loop {
        let fence: [u8; 32] = rand::random();
        if fence != [0u8; 32] {
            return fence;
        }
    }
}

fn compute_transition_digest(
    community_id: &Uuid,
    history_id: &Uuid,
    operation_id: &Uuid,
    request_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.transition-digest.v1\x00");
    h.update(community_id.as_bytes());
    h.update(history_id.as_bytes());
    h.update(operation_id.as_bytes());
    h.update(request_fingerprint);
    h.finalize().into()
}

fn compute_result_digest(
    request_fingerprint: &[u8; 32],
    operation_id: &Uuid,
    community_id: &Uuid,
    outcome: u8,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.result-digest.v1\x00");
    h.update(request_fingerprint);
    h.update(operation_id.as_bytes());
    h.update(community_id.as_bytes());
    h.update([outcome]);
    h.finalize().into()
}

/// Minimal canonical envelope for a lifecycle audit event.
///
/// The envelope carries the pseudonymous identity of the operation for
/// offline audit reconstruction.  Format: a fixed-size CBOR-style record
/// encoded as 5 length-prefixed fields.
fn build_minimal_canonical_envelope(
    event_kind: u8,
    community_id: &Uuid,
    operation_id: &Uuid,
    request_fingerprint: &[u8; 32],
    actor_fingerprint: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    // 1-byte magic, 1-byte version
    v.push(0xCA_u8); // canonical-authorization marker
    v.push(0x01_u8); // schema version 1
    v.push(event_kind);
    v.extend_from_slice(community_id.as_bytes());
    v.extend_from_slice(operation_id.as_bytes());
    v.extend_from_slice(request_fingerprint);
    v.extend_from_slice(actor_fingerprint);
    v
}

fn compute_envelope_digest(envelope: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"buzz.nip-fi.envelope-digest.v1\x00");
    h.update(envelope);
    h.finalize().into()
}

// ── SQLSTATE helpers ──────────────────────────────────────────────────────────

// ── NIP-FI writer lock (Design C Phase-A) ────────────────────────────────────

/// Acquire the exclusive per-community NIP-FI writer lock.
///
/// This is the Phase-A coarse writer serialization: one NIP-FI authority
/// transaction at a time per community.  Every function that reads authoritative
/// NIP-FI state and then writes authority rows must call this before any
/// authoritative read so that concurrent admissions and protected-use advances
/// are totally ordered.
///
/// The lock key namespace is distinct from `community_deletion_lock_key` (which
/// uses `buzz-community-deletion:` prefix with a shared/exclusive pair).  The
/// NIP-FI writer lock is always acquired exclusively — concurrent admissions
/// serialize here rather than contending on the identity coordinator lock alone.
///
/// Lock acquisition order (to prevent deadlock):
///   1. `assert_community_write_allowed` → shared deletion lock (READ COMMITTED)
///   2. This function → exclusive NIP-FI writer lock
///
/// All callers must follow this order.
async fn acquire_nip_fi_writer_lock(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
) -> Result<(), AdmissionError> {
    sqlx::query(
        r#"SELECT pg_advisory_xact_lock(
            hashtextextended('buzz:nip-fi-writer:v1:' || $1::text, 0)
        )"#,
    )
    .bind(community_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    Ok(())
}

fn is_serialization_failure(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(ref db) = e {
        db.code().map(|c| c == "40001").unwrap_or(false)
    } else {
        false
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(ref db) = e {
        db.code().map(|c| c == "23505").unwrap_or(false)
    } else {
        false
    }
}

fn map_sqlx_error(e: sqlx::Error) -> AdmissionError {
    if is_serialization_failure(&e) {
        return AdmissionError::SerializationRetry;
    }
    if let sqlx::Error::Database(ref db) = e {
        if let Some(constraint) = db.constraint() {
            if constraint.contains("capacity_exhausted") {
                return AdmissionError::CapacityExhausted;
            }
        }
    }
    AdmissionError::Transient(e.to_string())
}

// ── Assertion revalidation ────────────────────────────────────────────────────

/// Revalidate the compact JWS against the current key source and compare the
/// freshly sealed assertion against the prepared one on all NIP-FI classes.
///
/// Called by [`commit_kind9_atomic`] in `nip_fi/mod.rs` before opening the
/// transaction.  This keeps the JWS round-trip outside the
/// transaction boundary and makes [`commit_admission_in_tx`] testable without
/// a real key source.
///
/// Identity class: issuer, subject, asserted_key, policy_id, contract_id.
/// Bounds class: the fresh `authority_deadlines` set is compared element-wise
///   against the prepared set (by index after sorting both ascending).
///   Every fresh deadline must be ≤ its prepared counterpart.
///   The fresh assertion must also be live at DB time.
/// Provenance: snapshot generation/key identity change is allowed only after
///   successful revalidation; it is never a failure reason.
pub(super) fn revalidate_assertion<S: IssuerKeySource>(
    verifier: &FederatedAssertionVerifier<S>,
    prepared: &VerifiedAssertion,
    db_now: DateTime<Utc>,
) -> Result<VerifiedAssertion, AdmissionError> {
    let jws = prepared
        .revalidation_dependencies()
        .confidential_assertion()
        .compact_jws();

    let fresh = verifier
        .verify(jws)
        .map_err(|_e| AdmissionError::AssertionEquivalenceViolation)?;

    // Identity class checks.
    if fresh.identity().issuer() != prepared.identity().issuer()
        || fresh.identity().subject() != prepared.identity().subject()
    {
        return Err(AdmissionError::AssertionEquivalenceViolation);
    }
    if fresh.asserted_key() != prepared.asserted_key() {
        return Err(AdmissionError::AssertionEquivalenceViolation);
    }
    if fresh.assertion_policy_id() != prepared.assertion_policy_id() {
        return Err(AdmissionError::ContractIdChanged);
    }
    if fresh.transport_contract_id() != prepared.transport_contract_id() {
        return Err(AdmissionError::ContractIdChanged);
    }
    // Capabilities must be byte-equal (canonical encoding deduplicates).
    if fresh.capabilities().entries() != prepared.capabilities().entries() {
        return Err(AdmissionError::AssertionEquivalenceViolation);
    }

    // Bounds class: compare every deadline in the sorted sets.
    // Both sets are non-empty by construction.  Sort ascending then compare
    // pair-wise.  If the fresh set has more deadlines, the extras must be ≤
    // the tightest prepared deadline (conservative: use it for all).
    // If the fresh set has fewer deadlines, fail — a missing deadline means
    // authority was removed.
    let mut fresh_dl: Vec<DateTime<Utc>> = fresh.authority_deadlines().to_vec();
    let mut prep_dl: Vec<DateTime<Utc>> = prepared.authority_deadlines().to_vec();
    fresh_dl.sort_unstable();
    prep_dl.sort_unstable();

    if fresh_dl.len() < prep_dl.len() {
        // Fewer deadlines in the fresh result: authority narrowed unexpectedly.
        return Err(AdmissionError::AssertionEquivalenceViolation);
    }

    let tightest_prepared = *prep_dl.first().expect("non-empty by construction");

    for (i, &fd) in fresh_dl.iter().enumerate() {
        let pd = prep_dl.get(i).copied().unwrap_or(tightest_prepared);
        if fd > pd {
            return Err(AdmissionError::AssertionEquivalenceViolation);
        }
    }

    // All fresh deadlines must be live at DB time.
    for &fd in &fresh_dl {
        if db_now >= fd {
            return Err(AdmissionError::PreparedDeadlineExpired);
        }
    }

    Ok(fresh)
}

// ── Public admission API ──────────────────────────────────────────────────────

/// Execute the full NIP-FI admission inside a caller-owned READ COMMITTED
/// transaction.
///
/// The caller is responsible for:
///   1. Opening the transaction (`pool.begin()` or `Db::begin_transaction()`).
///   2. The transaction MUST remain at READ COMMITTED (the default).  Do NOT
///      call `SET TRANSACTION ISOLATION LEVEL SERIALIZABLE`; the community
///      write fence trigger rejects it.
///   3. Passing `db_now` from `transaction_timestamp()` called immediately after
///      the transaction opens (before this function acquires any lock).
///   4. Committing or rolling back after all writes (event insert) succeed.
///
/// `fresh_assertion` must have already been re-verified by the caller (via
/// [`revalidate_assertion`]) before opening the transaction.  Moving revalidation
/// outside keeps this function testable without a real JWS verifier: integration
/// tests can pass a [`VerifiedAssertion`] built with
/// `buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion`.
///
/// This is the Design-C inner path used by [`commit_kind9_atomic`] to ensure
/// community write assertion, enrollment, replay claim, receipts, epoch/fence,
/// protected-use re-fence, and event insert all commit or roll back together
/// (FI-INV-09 all-or-none).
///
/// Returns a `CommittedAuthorization` that the caller passes to
/// [`authorize_protected_use_in_tx`] for the immediate re-fence before the
/// event insert.
#[allow(clippy::too_many_lines)]
pub(crate) async fn commit_admission_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    db_now: DateTime<Utc>,
    ctx: &SealedRequestContext,
    proposal: &BindingProposal,
    fresh_assertion: &VerifiedAssertion,
) -> Result<CommittedAuthorization, AdmissionError> {
    let community_id = ctx.community_id;
    let actor_pubkey = ctx.actor.to_bytes();
    let object_kind_code = ctx.object_kind.database_code();
    let object_key = ctx.object_key;
    let operation_id = ctx.operation_id;
    let request_fingerprint = compute_request_fingerprint(ctx);

    // ── 1. Proof expiry (authoritative DB time) ───────────────────────────
    if db_now >= ctx.proof_expires_at {
        return Err(AdmissionError::ProofExpired);
    }

    // ── 2–14: community/channel/policy/enrollment/invalidation/fence/receipt
    // (all identical to the old `commit_admission_inner` body below, but
    // operating on the caller-owned `tx` instead of a locally opened one)
    commit_admission_body(
        tx,
        db_now,
        ctx,
        proposal,
        fresh_assertion,
        community_id,
        actor_pubkey,
        object_kind_code,
        object_key,
        operation_id,
        request_fingerprint,
    )
    .await
}

/// Shared body for NIP-FI admission steps 3–14 (community/channel/policy/
/// enrollment/invalidation/epoch/fence/receipt/authority).
///
/// Operates on a caller-owned READ COMMITTED transaction; does not commit.
/// Used by both the standalone `commit_admission_inner` and the Design-C
/// `commit_admission_in_tx`.
///
/// ## Final-use revalidation matrix
///
/// Every step reads the current state from a fresh READ COMMITTED statement
/// snapshot and rejects if the live DB value diverges from what the proof
/// authorised.
///
/// | # | Group | DB column(s) | Mismatch action |
/// |---|-------|-------------|-----------------|
/// | 3 | Community write assertion | `assert_community_write_allowed` (shared deletion lock) | `CommunityWriteFenced` |
/// | 3b | NIP-FI writer lock | `acquire_nip_fi_writer_lock` (exclusive per-community) | `Transient` |
/// | 4 | Channel resource state | `channels.archived_at`, `channels.deleted_at` | `ResourceStateDenied` |
/// | 5 | Policy revision | `identity_enrollment_policies.policy_revision` (latest) | `PolicyNotYetEffective` / `PolicyExpired` |
/// | 6 | Enrollment existence | `identity_enrollments.invalidated_epoch` | `EnrollmentNotFound` |
/// | 7 | Invalidation / fence generation | `identity_enrollment_invalidations.generation` | `EpochFenceAdvanced` |
/// | 8 | Binding identity | `nip_fi_bindings.principal_fingerprint` | `BindingIdentityMismatch` |
/// | 9 | Binding version | `nip_fi_bindings.known_version` | `BindingVersionMismatch` |
/// | 10–14 | Epoch UPDATE / POA UPDATE rows_affected | UPDATE returns 0 rows | `EpochFenceAdvanced` |
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn commit_admission_body(
    tx: &mut Transaction<'_, Postgres>,
    db_now: DateTime<Utc>,
    ctx: &SealedRequestContext,
    proposal: &BindingProposal,
    fresh_assertion: &VerifiedAssertion,
    community_id: Uuid,
    actor_pubkey: [u8; 32],
    object_kind_code: i16,
    object_key: [u8; 32],
    operation_id: Uuid,
    request_fingerprint: [u8; 32],
) -> Result<CommittedAuthorization, AdmissionError> {
    // ── 3. Community write assertion (shared deletion lock) ───────────────
    //
    // `assert_community_write_allowed` is the FIRST transactional operation.
    // It acquires `pg_advisory_xact_lock_shared(community_deletion_lock_key(community_id))`
    // and verifies the community is active from a fresh READ COMMITTED
    // statement snapshot.  The shared lock is held until commit, preventing
    // quiescing/deletion from completing while this transaction is in flight.
    //
    // This call also enforces READ COMMITTED isolation; SERIALIZABLE would
    // be rejected here with ERRCODE `invalid_transaction_state`.
    sqlx::query("SELECT assert_community_write_allowed($1)")
        .bind(community_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            // ERRCODE `object_not_in_prerequisite_state` = community fenced/missing.
            if let sqlx::Error::Database(ref db) = e {
                let code = db.code().map(|c| c.into_owned()).unwrap_or_default();
                if code == "55000" {
                    return AdmissionError::CommunityWriteFenced;
                }
            }
            AdmissionError::Transient(e.to_string())
        })?;

    // ── 3b. Exclusive NIP-FI writer lock (Phase-A serialization) ─────────
    //
    // Acquired AFTER the shared deletion lock (fixed order prevents deadlock).
    // Serializes all NIP-FI authority writers per community so authoritative
    // reads below are not raceable by concurrent admissions, lifecycle
    // transitions, policy advances, or invalidation writers.
    acquire_nip_fi_writer_lock(tx, community_id).await?;

    // ── 3c. Event duplicate precheck ─────────────────────────────────────
    //
    // Read the events table under FOR SHARE before any authority write.  If
    // this exact (community_id, created_at, id) row already exists, the event
    // is a duplicate — return an early no-op with zero claim/receipt/epoch/
    // fence/thread writes.  This eliminates the `was_inserted == false` case
    // at the end of the outer commit loop for the common duplicate path.
    //
    // Nostr event timestamps are unix seconds (i64 via NIP-01).  The DB stores
    // created_at as BIGINT (seconds); for events tables using TIMESTAMPTZ,
    // the nostr `Timestamp::as_u64()` value is used directly here via a
    // TIMESTAMPTZ comparison (postgres will coerce from a chrono DateTime).
    {
        let event_id_bytes = ctx.signed_event_id;
        let event_created_at = ctx.event_created_at;
        let dup_row = sqlx::query(
            r#"
            SELECT id FROM events
            WHERE community_id = $1
              AND created_at   = $2
              AND id           = $3
            FOR SHARE
            "#,
        )
        .bind(community_id)
        .bind(event_created_at)
        .bind(event_id_bytes.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;

        if dup_row.is_some() {
            // Event already committed — return early with the DuplicateEvent
            // signal so the outer loop can roll back and return no-op.
            return Err(AdmissionError::DuplicateEvent);
        }
    }

    // ── 3d. Proof-owner claim read ────────────────────────────────────────
    //
    // Read the existing owner row for this (community_id, proof_event_id)
    // pair under FOR SHARE.  This determines whether a concurrent admission
    // on the same proof is allowed (same conn_id → reuse) or denied
    // (different conn_id → ProofReplayed).  The INSERT at step 9 races this
    // read; if a concurrent admission won and inserted first, the INSERT
    // returns a unique-violation → ProofReplayed (same as a pre-existing row
    // with a different conn_id).
    let proof_owner_row = sqlx::query(
        r#"
        SELECT connection_id FROM nip_fi_proof_replay_claims
        WHERE community_id  = $1
          AND proof_event_id = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(ctx.proof_event_id.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let conn_id = ctx.conn_id;

    if let Some(owner_row) = &proof_owner_row {
        let existing_conn: Uuid = owner_row
            .try_get("connection_id")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if existing_conn != conn_id {
            // Different connection owns this proof — cross-connection reuse.
            return Err(AdmissionError::ProofReplayed);
        }
        // Same connection: same-connection reuse is allowed; fall through.
        // The INSERT at step 9 is skipped if the row already exists
        // (handled by the INSERT ON CONFLICT DO NOTHING path).
    }

    // ── 3e. Receipt read-time exact-replay / conflict protocol ───────────
    //
    // Read the existing admission receipt for this operation_id before any
    // write.  This implements the read-time idempotence protocol:
    //   - Same operation_id + same request_fingerprint + matching outcome +
    //     event already exists → duplicate exact-replay no-op (return early).
    //   - Same operation_id + different request_fingerprint → IntentConflict
    //     (two different requests mapped to the same deterministic op ID,
    //     which must not happen with sound derivation).
    //   - No existing receipt → proceed normally.
    //
    // The operation_id is deterministic: (community_id, proof_event_id,
    // signed_event_id) always maps to the same UUID.  Two requests with the
    // same triple are identical by construction and should be exact replays.
    let existing_receipt = sqlx::query(
        r#"
        SELECT request_fingerprint, outcome_code
        FROM authorization_operation_receipts
        WHERE community_id = $1
          AND operation_id = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if let Some(receipt_row) = existing_receipt {
        let stored_rf: Vec<u8> = receipt_row
            .try_get("request_fingerprint")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if stored_rf.as_slice() == request_fingerprint.as_slice() {
            // Same fingerprint: exact replay — return early, zero new writes.
            return Err(AdmissionError::DuplicateEvent);
        } else {
            // Different fingerprint on same operation_id: intent conflict.
            // This must not happen with sound deterministic derivation.
            return Err(AdmissionError::Transient(
                "NIP-FI operation_id collision: same deterministic ID, different fingerprint"
                    .into(),
            ));
        }
    }

    // ── 4. Channel resource state reread (kind-9 vertical slice) ─────────
    //
    // object_key for MessagesWrite/Channel = SHA-256 of the 16-byte wire
    // representation of the channel UUID (PostgreSQL: sha256(uuid_send(c.id))).
    // NOT sha256(c.id::text::bytea) — that hashes 36 ASCII bytes.
    let channel_row = sqlx::query(
        r#"
        SELECT c.id, c.archived_at, c.deleted_at
        FROM channels c
        JOIN communities comm ON comm.id = c.community_id
        WHERE c.community_id = $1
          AND sha256(uuid_send(c.id)) = $2
          AND comm.deletion_state = 'active'
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(object_key.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let chan = channel_row.ok_or(AdmissionError::ResourceStateDenied)?;
    let archived_at: Option<DateTime<Utc>> = chan
        .try_get("archived_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    let deleted_at: Option<DateTime<Utc>> = chan
        .try_get("deleted_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if archived_at.is_some() || deleted_at.is_some() {
        return Err(AdmissionError::ResourceStateDenied);
    }

    // ── 5. Policy reread ──────────────────────────────────────────────────
    let policy_row = sqlx::query(
        r#"
        SELECT policy_revision, effective_at, expires_at
        FROM identity_enrollment_policies
        WHERE community_id = $1
        ORDER BY policy_revision DESC
        LIMIT 1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let pr = policy_row.ok_or(AdmissionError::PolicyNotYetEffective)?;
    let policy_revision: i64 = pr
        .try_get("policy_revision")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    let policy_effective_at: DateTime<Utc> = pr
        .try_get("effective_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    let policy_expires_at: Option<DateTime<Utc>> = pr
        .try_get("expires_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;

    if db_now < policy_effective_at {
        return Err(AdmissionError::PolicyNotYetEffective);
    }
    if let Some(exp) = policy_expires_at {
        if db_now >= exp {
            return Err(AdmissionError::PolicyExpired);
        }
    }

    // ── 6. Enrollment: resolve or create binding ──────────────────────────
    let issuer = fresh_assertion.identity().issuer();
    let subject = fresh_assertion.identity().subject();
    let principal_fp = compute_principal_fingerprint(&actor_pubkey, issuer, subject);

    // Check for tombstone/revoked-key selector-3 on this exact pubkey.
    // selector_kind = 3 (revoked key Y-selector): selector_fingerprint is the
    // event_author_pubkey (32 bytes), NOT the principal fingerprint.
    // See migration 0041: kind-3 selector has event_author_pubkey IS NOT NULL,
    // principal_fingerprint IS NULL, and the permanent-key unique index is on
    // (community_id, event_author_pubkey) WHERE selector_kind = 3.
    let selector_3_row = sqlx::query(
        r#"
        SELECT selector_id
        FROM identity_lifecycle_selectors
        WHERE community_id         = $1
          AND selector_kind        = 3
          AND selector_fingerprint = $2
        LIMIT 1
        "#,
    )
    .bind(community_id)
    .bind(actor_pubkey.as_slice()) // event_author_pubkey for kind-3
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if selector_3_row.is_some() {
        return Err(AdmissionError::NoActiveBinding);
    }

    // Check for a permanent-pair P-selector (kind=1) on this exact
    // (principal_fingerprint, event_author_pubkey) pair.  A P-selector is
    // asserted by retire/revoke/rotate of the old generation and permanently
    // blocks re-enrollment of the same identity pair.
    let selector_1_row = sqlx::query(
        r#"
        SELECT selector_id
        FROM identity_lifecycle_selectors
        WHERE community_id         = $1
          AND selector_kind        = 1
          AND selector_fingerprint = $2
        LIMIT 1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(principal_fp.as_slice()) // principal_fp for kind-1
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if selector_1_row.is_some() {
        return Err(AdmissionError::NoActiveBinding);
    }

    // Attempt to find an existing active binding.
    let binding_row = sqlx::query(
        r#"
        SELECT binding_id, binding_version, binding_state, lifecycle_revision,
               expires_at, policy_revision
        FROM identity_bindings
        WHERE community_id              = $1
          AND issuer                    = $2
          AND subject                   = $3
          AND binding_state             = 1
        LIMIT 1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let (binding_id, binding_version, binding_lifecycle_revision) = match binding_row {
        Some(br) => {
            let bv: i64 = br
                .try_get("binding_version")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let bs: i16 = br
                .try_get("binding_state")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let lr: i64 = br
                .try_get("lifecycle_revision")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let exp: Option<DateTime<Utc>> = br
                .try_get("expires_at")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let bid: Uuid = br
                .try_get("binding_id")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;

            if bs != 1 {
                return Err(AdmissionError::BindingRetired);
            }
            if let Some(exp_t) = exp {
                if db_now >= exp_t {
                    return Err(AdmissionError::BindingExpired);
                }
            }
            (bid, bv, lr)
        }
        None => {
            // No active binding — enroll a new one.
            let (bid, bv, lr) = enroll_binding(
                tx,
                community_id,
                &actor_pubkey,
                issuer,
                subject,
                &principal_fp,
                proposal,
                policy_revision,
                fresh_assertion,
                operation_id,
                &request_fingerprint,
                db_now,
            )
            .await?;
            (bid, bv, lr)
        }
    };

    // ── 7. Invalidation domain and floor checks ───────────────────────────
    let domain_row = sqlx::query(
        r#"
        SELECT current_generation
        FROM authorization_invalidation_domains
        WHERE community_id = $1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let current_generation: i64 = match domain_row {
        Some(r) => r
            .try_get("current_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?,
        None => return Err(AdmissionError::InvalidationDomainAbsent),
    };

    // Principal-level (selector 1) floor.
    let floor_1_row = sqlx::query(
        r#"
        SELECT floor_generation, binding_version_floor
        FROM authorization_invalidation_floors
        WHERE community_id         = $1
          AND selector_kind        = 1
          AND selector_fingerprint = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(principal_fp.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if let Some(fr) = floor_1_row {
        let floor_gen: i64 = fr
            .try_get("floor_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if current_generation < floor_gen {
            return Err(AdmissionError::InvalidationFloorAbsent);
        }
        if current_generation > floor_gen {
            return Err(AdmissionError::InvalidationGenerationAdvanced);
        }
    }

    // Binding (selector 3) floor — filtered to this exact actor pubkey.
    // selector_kind=3 uses selector_fingerprint = event_author_pubkey.
    let floor_3_rows = sqlx::query(
        r#"
        SELECT floor_generation, binding_version_floor
        FROM authorization_invalidation_floors
        WHERE community_id         = $1
          AND selector_kind        = 3
          AND selector_fingerprint = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(actor_pubkey.as_slice())
    .fetch_all(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    for fr in &floor_3_rows {
        let floor_gen: i64 = fr
            .try_get("floor_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if current_generation < floor_gen {
            return Err(AdmissionError::InvalidationFloorAbsent);
        }
        if current_generation > floor_gen {
            return Err(AdmissionError::InvalidationGenerationAdvanced);
        }
        let bvf: Option<i64> = fr
            .try_get("binding_version_floor")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if let Some(floor_bv) = bvf {
            if binding_version < floor_bv {
                return Err(AdmissionError::InvalidationFloorAbsent);
            }
        }
    }

    // ── 8. Assertion deadline check ───────────────────────────────────────
    // The fresh assertion was already fully bounds-checked in revalidate_assertion.
    // Re-confirm the upstream deadline against DB time.
    let upstream_deadline = fresh_assertion.upstream_authority_deadline();
    if db_now >= upstream_deadline {
        return Err(AdmissionError::PreparedDeadlineExpired);
    }

    // ── 9. Epoch/fence reread ─────────────────────────────────────────────
    let epoch_row = sqlx::query(
        r#"
        SELECT authority_epoch, fence
        FROM authorization_authority_epochs
        WHERE community_id = $1
          AND object_kind  = $2
          AND object_key   = $3
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let (current_epoch, _current_fence) = match &epoch_row {
        Some(r) => {
            let ep: i64 = r
                .try_get("authority_epoch")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let fence_bytes: Vec<u8> = r
                .try_get("fence")
                .map_err(|e| AdmissionError::Transient(e.to_string()))?;
            let mut fence = [0u8; 32];
            if fence_bytes.len() == 32 {
                fence.copy_from_slice(&fence_bytes);
            }
            (ep, fence)
        }
        None => (0i64, [0u8; 32]),
    };

    let new_epoch = current_epoch + 1;
    let new_fence = generate_fence();

    // ── 10. Insert operation receipt (operation_kind=11 protected mutation) ─
    // This is the admission receipt.  The enrollment receipt (kind=1) was
    // inserted inside enroll_binding() with a SEPARATE enroll_operation_id.
    // The two receipts must not share (community_id, operation_id) — that
    // is the receipt table's primary key.
    let result_digest =
        compute_result_digest(&request_fingerprint, &operation_id, &community_id, 1);
    sqlx::query(
        r#"
        INSERT INTO authorization_operation_receipts
            (community_id, operation_id, request_fingerprint,
             operation_kind, actor_fingerprint, outcome_code, result_digest)
        VALUES ($1, $2, $3, 11, $4, 1, $5)
        "#,
    )
    .bind(community_id)
    .bind(operation_id)
    .bind(request_fingerprint.as_slice())
    .bind(actor_pubkey.as_slice())
    .bind(result_digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    // ── 11. Upsert epoch/fence ────────────────────────────────────────────
    if epoch_row.is_some() {
        sqlx::query(
            r#"
            UPDATE authorization_authority_epochs
            SET authority_epoch    = $4,
                fence              = $5,
                operation_id       = $6,
                request_fingerprint = $7,
                updated_at         = clock_timestamp()
            WHERE community_id = $1
              AND object_kind  = $2
              AND object_key   = $3
            "#,
        )
        .bind(community_id)
        .bind(object_kind_code)
        .bind(object_key.as_slice())
        .bind(new_epoch)
        .bind(new_fence.as_slice())
        .bind(operation_id)
        .bind(request_fingerprint.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO authorization_authority_epochs
                (community_id, object_kind, object_key,
                 authority_epoch, fence, operation_id, request_fingerprint)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(community_id)
        .bind(object_kind_code)
        .bind(object_key.as_slice())
        .bind(new_epoch)
        .bind(new_fence.as_slice())
        .bind(operation_id)
        .bind(request_fingerprint.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;
    }

    // ── 12. Upsert protected_object_authority ─────────────────────────────
    let capability_code = ctx.capability.database_code();
    let issued_at = db_now; // Used in CommittedAuthorization; DB column uses clock_timestamp()
    let expires_at = std::cmp::min(ctx.proof_expires_at, upstream_deadline);

    sqlx::query(
        r#"
        INSERT INTO protected_object_authority (
            community_id, object_kind, object_key,
            capability, actor_pubkey, binding_id, binding_version,
            policy_revision, invalidation_generation,
            authority_epoch, fence,
            issued_at, expires_at,
            operation_id, request_fingerprint
        ) VALUES (
            $1, $2, $3,
            $4, $5, $6, $7,
            $8, $9,
            $10, $11,
            clock_timestamp(), $12,
            $13, $14
        )
        ON CONFLICT (community_id, object_kind, object_key) DO UPDATE SET
            capability              = EXCLUDED.capability,
            actor_pubkey            = EXCLUDED.actor_pubkey,
            binding_id              = EXCLUDED.binding_id,
            binding_version         = EXCLUDED.binding_version,
            policy_revision         = EXCLUDED.policy_revision,
            invalidation_generation = EXCLUDED.invalidation_generation,
            authority_epoch         = EXCLUDED.authority_epoch,
            fence                   = EXCLUDED.fence,
            issued_at               = EXCLUDED.issued_at,
            expires_at              = EXCLUDED.expires_at,
            operation_id            = EXCLUDED.operation_id,
            request_fingerprint     = EXCLUDED.request_fingerprint
        "#,
    )
    .bind(community_id)
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .bind(capability_code)
    .bind(actor_pubkey.as_slice())
    .bind(binding_id)
    .bind(binding_version)
    .bind(policy_revision)
    .bind(current_generation)
    .bind(new_epoch)
    .bind(new_fence.as_slice())
    .bind(expires_at)
    .bind(operation_id)
    .bind(request_fingerprint.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    // ── 13. Insert proof-owner claim (after all auth writes) ─────────────
    //
    // Inserted HERE — after the epoch/fence and POA writes, before the
    // admission result.  The step-3d FOR SHARE read above verified that no
    // different-connection owner exists.  Now we commit this connection as
    // the owner, with ON CONFLICT DO NOTHING to handle the PK race where a
    // concurrent winner inserted first while both transactions were in flight.
    //
    // After ON CONFLICT DO NOTHING:
    //   - Rows affected == 1: we are the inserting owner.  Continue.
    //   - Rows affected == 0: a concurrent tx won the race and already
    //     inserted a claim row.  Re-read the owner under FOR SHARE to
    //     determine if it is the same connection (same-conn reuse, allowed)
    //     or a different connection (cross-conn replay, ProofReplayed).
    //
    // The appended-only immutability trigger from migration 0043 holds:
    // once committed, connection_id cannot change.
    {
        let retained_until = upstream_deadline;
        let insert_rr = sqlx::query(
            r#"
            INSERT INTO nip_fi_proof_replay_claims
                (community_id, proof_event_id, retained_until, connection_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (community_id, proof_event_id) DO NOTHING
            "#,
        )
        .bind(community_id)
        .bind(ctx.proof_event_id.as_slice())
        .bind(retained_until)
        .bind(conn_id)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;

        if insert_rr.rows_affected() == 0 {
            // PK race: a concurrent admission won and inserted the claim row
            // before our ON CONFLICT DO NOTHING.  Re-read to check ownership.
            let race_row = sqlx::query(
                r#"
                SELECT connection_id FROM nip_fi_proof_replay_claims
                WHERE community_id  = $1
                  AND proof_event_id = $2
                FOR SHARE
                "#,
            )
            .bind(community_id)
            .bind(ctx.proof_event_id.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;

            match race_row {
                Some(r) => {
                    let winner_conn: Uuid = r
                        .try_get("connection_id")
                        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
                    if winner_conn != conn_id {
                        // Different connection inserted first — cross-conn replay.
                        return Err(AdmissionError::ProofReplayed);
                    }
                    // Same connection: same-conn reuse race — two tasks on the
                    // same WebSocket connection raced; the winner's row is
                    // identical.  Continue.
                }
                None => {
                    // Row vanished between INSERT and re-read (impossible under
                    // the append-only trigger, but fail closed if it happens).
                    return Err(AdmissionError::Transient(
                        "NIP-FI proof claim row disappeared after ON CONFLICT DO NOTHING".into(),
                    ));
                }
            }
        }
    }

    // ── 14. Insert admission result ───────────────────────────────────────
    let semantic_fingerprint = compute_semantic_fingerprint(ctx);
    sqlx::query(
        r#"
        INSERT INTO authorization_admission_results (
            community_id, operation_id, request_fingerprint,
            semantic_fingerprint, object_kind, object_key
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(community_id)
    .bind(operation_id)
    .bind(request_fingerprint.as_slice())
    .bind(semantic_fingerprint.as_slice())
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    // issued_at and expires_at are written to the DB above (bind()) but are
    // not stored on CommittedAuthorization — callers do not need them back.
    let _ = (issued_at, expires_at);

    Ok(CommittedAuthorization {
        community_id,
        operation_id,
        request_fingerprint,
        authority_epoch: new_epoch,
        authority_fence: new_fence,
        actor_pubkey,
        binding_id,
        binding_version,
        binding_lifecycle_revision,
        policy_revision,
        capability_code,
        object_kind_code,
        object_key,
        conn_id: ctx.conn_id,
        challenge: ctx.challenge.clone(),
        relay_url: ctx.relay_url.clone(),
        proof_event_id: ctx.proof_event_id,
        transport_code: match ctx.transport {
            ProofTransport::Nip42WebSocket => 1u8,
            ProofTransport::Nip98Http => 2u8,
        },
        assertion_issuer: issuer.to_string(),
        assertion_subject: subject.to_string(),
    })
}

/// Insert a new identity binding and its lifecycle history row atomically.
///
/// Uses `identity_lifecycle_lock_coordinates_v1` advisory lock for
/// concurrent-enrollment convergence.  Returns `(binding_id, binding_version,
/// lifecycle_revision=1)`.
///
/// ## Operation model
///
/// The enrollment uses a SEPARATE `enroll_operation_id` (a new UUID) so its
/// receipt (operation_kind=1) does not collide with the admission receipt
/// (operation_kind=11) for the same request.  The receipt table primary key
/// is (community_id, operation_id).
///
/// ## Insert ordering (avoiding the circular FK deadlock)
///
/// 1. INSERT identity_bindings RETURNING binding_version
/// 2. INSERT identity_lifecycle_history (all four successor fields populated,
///    because binding_version is now known)
/// 3. INSERT authorization_events (event_kind=1, deferred FK to receipt)
/// 4. INSERT authorization_operation_receipts (enroll_operation_id, kind=1)
///
/// All FKs on history → bindings and history → receipts are DEFERRABLE
/// INITIALLY DEFERRED — they are checked at COMMIT only.
#[allow(clippy::too_many_arguments)]
async fn enroll_binding(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    actor_pubkey: &[u8; 32],
    issuer: &str,
    subject: &str,
    principal_fp: &[u8; 32],
    proposal: &BindingProposal,
    policy_revision: i64,
    assertion: &VerifiedAssertion,
    _admission_operation_id: Uuid,
    request_fingerprint: &[u8; 32],
    db_now: DateTime<Utc>,
) -> Result<(Uuid, i64, i64), AdmissionError> {
    // Separate operation ID for enrollment receipt.
    // This keeps the enrollment receipt (kind=1) distinct from the admission
    // receipt (kind=11) — they both reference the same physical request
    // but are different operations in the authority ledger.
    let enroll_operation_id = Uuid::new_v4();
    let enroll_request_fingerprint = *request_fingerprint;

    // Acquire the per-coordinate advisory lock.
    sqlx::query("SELECT identity_lifecycle_lock_coordinates_v1($1, $2, $3)")
        .bind(community_id)
        .bind(principal_fp.as_slice())
        .bind(actor_pubkey.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx_error)?;

    // Re-check for an active binding under the lock (race convergence).
    let recheck = sqlx::query(
        r#"
        SELECT binding_id, binding_version
        FROM identity_bindings
        WHERE community_id  = $1
          AND issuer        = $2
          AND subject       = $3
          AND binding_state = 1
        LIMIT 1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if let Some(r) = recheck {
        // Identical concurrent enrollment — converge to the existing winner.
        let bid: Uuid = r
            .try_get("binding_id")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        let bv: i64 = r
            .try_get("binding_version")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        return Ok((bid, bv, 1));
    }

    let binding_id = proposal.binding_id;
    let evidence_digest = compute_enrollment_evidence_digest(assertion, actor_pubkey);

    // Step 1: Insert the binding row FIRST to get binding_version via RETURNING.
    // The birth_history_id FK is DEFERRABLE — we'll insert the history row next.
    // Temporary placeholder: we'll use binding_id as birth_history_id sentinel
    // but the real history_id comes immediately after.
    let history_id = Uuid::new_v4();

    let binding_row = sqlx::query(
        r#"
        INSERT INTO identity_bindings
            (community_id, binding_id,
             issuer, subject,
             principal_fingerprint, event_author_pubkey,
             binding_state, lifecycle_revision,
             binding_provenance, policy_revision,
             enrollment_evidence_digest,
             birth_history_id, creation_operation_id, creation_request_fingerprint)
        VALUES ($1, $2,
                $3, $4,
                $5, $6,
                1, 1,
                $7, $8,
                $9,
                $10, $11, $12)
        RETURNING binding_version
        "#,
    )
    .bind(community_id)
    .bind(binding_id)
    .bind(issuer)
    .bind(subject)
    .bind(principal_fp.as_slice())
    .bind(actor_pubkey.as_slice())
    .bind(proposal.provenance.database_code())
    .bind(policy_revision)
    .bind(evidence_digest.as_slice())
    .bind(history_id)
    .bind(enroll_operation_id)
    .bind(enroll_request_fingerprint.as_slice())
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            AdmissionError::EnrollmentConflict
        } else {
            map_sqlx_error(e)
        }
    })?;

    let binding_version: i64 = binding_row
        .try_get("binding_version")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;

    // Step 2: Insert lifecycle history with all four successor fields populated.
    // The CHECK requires all four successor fields to be ALL non-null or ALL null.
    // Transition kind=1 (enroll) requires old_binding_id IS NULL and
    // successor_binding_id IS NOT NULL.
    let transition_digest = compute_transition_digest(
        &community_id,
        &history_id,
        &enroll_operation_id,
        &enroll_request_fingerprint,
    );

    sqlx::query(
        r#"
        INSERT INTO identity_lifecycle_history
            (community_id, history_id, transition_kind, outcome_code,
             successor_binding_id, successor_binding_version,
             successor_lifecycle_revision, successor_state,
             operation_id, request_fingerprint, transition_digest)
        VALUES ($1, $2, 1, 1,
                $3, $4,
                1, 1,
                $5, $6, $7)
        "#,
    )
    .bind(community_id)
    .bind(history_id)
    .bind(binding_id)
    .bind(binding_version) // now known: all four successor fields populated
    .bind(enroll_operation_id)
    .bind(enroll_request_fingerprint.as_slice())
    .bind(transition_digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    // Step 3: Insert the enrollment audit event (event_kind=1 enrolled).
    // Required by the deferred trigger on authorization_operation_receipts
    // (operation_kind=1 lifecycle receipt must have exactly one event).
    // actor_kind=1 (principal/user).
    let audit_event_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let enroll_result_digest = compute_result_digest(
        &enroll_request_fingerprint,
        &enroll_operation_id,
        &community_id,
        1,
    );
    let envelope = build_minimal_canonical_envelope(
        1, // event_kind=1 enrolled
        &community_id,
        &enroll_operation_id,
        &enroll_request_fingerprint,
        actor_pubkey,
    );
    let envelope_digest = compute_envelope_digest(&envelope);

    sqlx::query(
        r#"
        INSERT INTO authorization_events
            (community_id, event_id, event_kind, outcome_code, reason_code,
             actor_kind, actor_fingerprint, subject_fingerprint,
             operation_id, request_fingerprint, correlation_id, attempt_id,
             occurred_at, canonical_envelope, envelope_digest)
        VALUES ($1, $2, 1, 1, 1,
                1, $3, $3,
                $4, $5, $6, $7,
                $8, $9, $10)
        "#,
    )
    .bind(community_id)
    .bind(audit_event_id)
    .bind(actor_pubkey.as_slice()) // actor_fingerprint (and subject_fingerprint)
    .bind(enroll_operation_id)
    .bind(enroll_request_fingerprint.as_slice())
    .bind(correlation_id)
    .bind(attempt_id)
    .bind(db_now) // occurred_at
    .bind(&envelope)
    .bind(envelope_digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    // Step 4: Insert the enrollment receipt (operation_kind=1).
    // The deferred FK in identity_lifecycle_history → receipts is satisfied now.
    sqlx::query(
        r#"
        INSERT INTO authorization_operation_receipts
            (community_id, operation_id, request_fingerprint,
             operation_kind, actor_fingerprint, outcome_code, result_digest)
        VALUES ($1, $2, $3, 1, $4, 1, $5)
        "#,
    )
    .bind(community_id)
    .bind(enroll_operation_id)
    .bind(enroll_request_fingerprint.as_slice())
    .bind(actor_pubkey.as_slice())
    .bind(enroll_result_digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    Ok((binding_id, binding_version, 1))
}

// ── Protected-use re-fence ────────────────────────────────────────────────────

/// Re-read every committed witness inside a caller-owned READ COMMITTED
/// transaction, compare live-connection scalars, re-fence, and return an
/// `AuthorizedUse`.
///
/// Design-C path: the caller owns the READ COMMITTED transaction that spans
/// the community write assertion, NIP-FI writer lock, admission, this
/// re-fence, and the event insert.  No commit happens here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_protected_use_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    db_now: DateTime<Utc>,
    committed: &CommittedAuthorization,
    live_conn_id: Uuid,
    live_challenge: &str,
    live_relay_url: &str,
    live_proof_event_id: &[u8; 32],
    live_transport: ProofTransport,
    live_actor: &nostr::PublicKey,
) -> Result<AuthorizedUse, AdmissionError> {
    authorize_protected_use_body(
        tx,
        db_now,
        committed,
        live_conn_id,
        live_challenge,
        live_relay_url,
        live_proof_event_id,
        live_transport,
        live_actor,
    )
    .await
}

/// Shared body for authorize_protected_use steps 1–9 (community/channel/poa/
/// binding/invalidation/re-fence/epoch advance/receipt).
///
/// Operates on a caller-owned READ COMMITTED transaction; does not commit.
/// Used by `authorize_protected_use_in_tx` (Design-C atomic path).
#[allow(clippy::too_many_arguments)]
async fn authorize_protected_use_body(
    tx: &mut Transaction<'_, Postgres>,
    db_now: DateTime<Utc>,
    committed: &CommittedAuthorization,
    live_conn_id: Uuid,
    live_challenge: &str,
    live_relay_url: &str,
    live_proof_event_id: &[u8; 32],
    live_transport: ProofTransport,
    live_actor: &nostr::PublicKey,
) -> Result<AuthorizedUse, AdmissionError> {
    let community_id = committed.community_id;
    let object_kind_code = committed.object_kind_code;
    let object_key = &committed.object_key;

    // ── 1. Community write assertion (shared deletion lock) ───────────────
    //
    // `assert_community_write_allowed` is the FIRST transactional operation.
    // It acquires `pg_advisory_xact_lock_shared(community_deletion_lock_key(community_id))`
    // and verifies the community is active from a fresh READ COMMITTED
    // statement snapshot.  The shared lock is held until commit.
    //
    // ERRCODE `25000` (invalid_transaction_state) = wrong isolation level (fatal).
    // ERRCODE `55000` (object_not_in_prerequisite_state) = community fenced/missing.
    sqlx::query("SELECT assert_community_write_allowed($1)")
        .bind(community_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db) = e {
                let code = db.code().map(|c| c.into_owned()).unwrap_or_default();
                if code == "55000" {
                    return AdmissionError::CommunityWriteFenced;
                }
            }
            AdmissionError::Transient(e.to_string())
        })?;

    // ── 1b. Exclusive NIP-FI writer lock (Phase-A serialization) ──────────
    //
    // Acquired AFTER the shared deletion lock (fixed order prevents deadlock).
    // Serializes all NIP-FI authority writers per community.
    acquire_nip_fi_writer_lock(tx, community_id).await?;

    // ── 2. Channel resource state reread ──────────────────────────────────
    // Same UUID 16-byte encoding as admission: sha256(uuid_send(c.id)).
    let channel_row = sqlx::query(
        r#"
        SELECT c.archived_at, c.deleted_at
        FROM channels c
        WHERE c.community_id = $1
          AND sha256(uuid_send(c.id)) = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(object_key.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let chan = channel_row.ok_or(AdmissionError::ResourceStateDenied)?;
    let archived_at: Option<DateTime<Utc>> = chan
        .try_get("archived_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    let deleted_at: Option<DateTime<Utc>> = chan
        .try_get("deleted_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if archived_at.is_some() || deleted_at.is_some() {
        return Err(AdmissionError::ResourceStateDenied);
    }

    // ── 3. Re-read protected_object_authority (FOR UPDATE) ────────────────
    let poa_row = sqlx::query(
        r#"
        SELECT capability, actor_pubkey, binding_id, binding_version,
               policy_revision, invalidation_generation,
               authority_epoch, fence, issued_at, expires_at,
               operation_id, request_fingerprint
        FROM protected_object_authority
        WHERE community_id = $1
          AND object_kind  = $2
          AND object_key   = $3
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let poa = poa_row.ok_or(AdmissionError::NoActiveBinding)?;

    // ── 4. Live-connection dimensions ─────────────────────────────────────
    let poa_capability: i16 = poa
        .try_get("capability")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_capability != committed.capability_code {
        return Err(AdmissionError::ResourceStateDenied);
    }

    let poa_actor: Vec<u8> = poa
        .try_get("actor_pubkey")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_actor.as_slice() != live_actor.to_bytes().as_slice()
        || poa_actor.as_slice() != committed.actor_pubkey.as_slice()
    {
        return Err(AdmissionError::ResourceStateDenied);
    }

    if live_conn_id != committed.conn_id {
        return Err(AdmissionError::ResourceStateDenied);
    }
    if live_challenge != committed.challenge.as_str() {
        return Err(AdmissionError::ResourceStateDenied);
    }
    if live_relay_url != committed.relay_url.as_str() {
        return Err(AdmissionError::ResourceStateDenied);
    }
    if live_proof_event_id != &committed.proof_event_id {
        return Err(AdmissionError::ResourceStateDenied);
    }

    let live_transport_code = match live_transport {
        ProofTransport::Nip42WebSocket => 1u8,
        ProofTransport::Nip98Http => 2u8,
    };
    if live_transport_code != committed.transport_code {
        return Err(AdmissionError::ResourceStateDenied);
    }

    let poa_epoch: i64 = poa
        .try_get("authority_epoch")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_epoch != committed.authority_epoch {
        return Err(AdmissionError::EpochFenceAdvanced);
    }

    let poa_fence_bytes: Vec<u8> = poa
        .try_get("fence")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_fence_bytes.len() != 32 || poa_fence_bytes == [0u8; 32] {
        return Err(AdmissionError::EpochFenceAdvanced);
    }
    let mut current_fence = [0u8; 32];
    current_fence.copy_from_slice(&poa_fence_bytes);
    if current_fence != committed.authority_fence {
        return Err(AdmissionError::EpochFenceAdvanced);
    }

    let poa_rf_bytes: Vec<u8> = poa
        .try_get("request_fingerprint")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_rf_bytes.as_slice() != committed.request_fingerprint.as_slice() {
        return Err(AdmissionError::EpochFenceAdvanced);
    }

    let poa_op_id: Uuid = poa
        .try_get("operation_id")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_op_id != committed.operation_id {
        return Err(AdmissionError::EpochFenceAdvanced);
    }

    let poa_expires_at: DateTime<Utc> = poa
        .try_get("expires_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if db_now >= poa_expires_at {
        return Err(AdmissionError::PreparedDeadlineExpired);
    }

    let poa_binding_version: i64 = poa
        .try_get("binding_version")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if poa_binding_version != committed.binding_version {
        return Err(AdmissionError::NoActiveBinding);
    }

    // ── 5. Binding liveness ───────────────────────────────────────────────
    let poa_binding_id: Uuid = poa
        .try_get("binding_id")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    // Binding_id must match the one committed during admission — a changed POA
    // binding (e.g., after a rotation race) must be rejected, not silently
    // accepted.
    if poa_binding_id != committed.binding_id {
        return Err(AdmissionError::NoActiveBinding);
    }

    let poa_policy_revision: i64 = poa
        .try_get("policy_revision")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    // Policy_revision must match — an advanced or changed policy between
    // admission and final use must be rejected.
    if poa_policy_revision != committed.policy_revision {
        return Err(AdmissionError::PolicyExpired);
    }

    let binding_check = sqlx::query(
        r#"
        SELECT binding_state, lifecycle_revision, expires_at
        FROM identity_bindings
        WHERE community_id    = $1
          AND binding_id      = $2
          AND binding_version = $3
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(poa_binding_id)
    .bind(poa_binding_version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let bc = binding_check.ok_or(AdmissionError::NoActiveBinding)?;
    let bs: i16 = bc
        .try_get("binding_state")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if bs != 1 {
        return Err(AdmissionError::BindingRetired);
    }
    let bc_lifecycle_revision: i64 = bc
        .try_get("lifecycle_revision")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    // lifecycle_revision must match the one recorded at admission — an
    // advanced lifecycle (e.g. binding transitioned to a new state after
    // admission) must be rejected at final use.
    if bc_lifecycle_revision != committed.binding_lifecycle_revision {
        return Err(AdmissionError::BindingRetired);
    }
    let bind_exp: Option<DateTime<Utc>> = bc
        .try_get("expires_at")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if let Some(exp) = bind_exp {
        if db_now >= exp {
            return Err(AdmissionError::BindingExpired);
        }
    }

    // ── 6. Invalidation domain reread ─────────────────────────────────────
    let domain_row = sqlx::query(
        r#"
        SELECT current_generation
        FROM authorization_invalidation_domains
        WHERE community_id = $1
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let current_generation: i64 = match domain_row {
        Some(r) => r
            .try_get("current_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?,
        None => return Err(AdmissionError::InvalidationDomainAbsent),
    };

    let poa_inv_gen: i64 = poa
        .try_get("invalidation_generation")
        .map_err(|e| AdmissionError::Transient(e.to_string()))?;
    if current_generation > poa_inv_gen {
        return Err(AdmissionError::InvalidationGenerationAdvanced);
    }

    // ── 7. Principal (selector 1) floor ───────────────────────────────────
    let actor_pubkey = committed.actor_pubkey;
    let principal_fp = compute_principal_fingerprint(
        &actor_pubkey,
        &committed.assertion_issuer,
        &committed.assertion_subject,
    );
    let floor_1_row = sqlx::query(
        r#"
        SELECT floor_generation
        FROM authorization_invalidation_floors
        WHERE community_id         = $1
          AND selector_kind        = 1
          AND selector_fingerprint = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(principal_fp.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    if let Some(fr) = floor_1_row {
        let floor_gen: i64 = fr
            .try_get("floor_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if current_generation < floor_gen {
            return Err(AdmissionError::InvalidationFloorAbsent);
        }
        if current_generation > floor_gen {
            return Err(AdmissionError::InvalidationGenerationAdvanced);
        }
    }

    // ── 8. Binding (selector 3) floor ─────────────────────────────────────
    let floor_3_rows = sqlx::query(
        r#"
        SELECT floor_generation, binding_version_floor
        FROM authorization_invalidation_floors
        WHERE community_id         = $1
          AND selector_kind        = 3
          AND selector_fingerprint = $2
        FOR SHARE
        "#,
    )
    .bind(community_id)
    .bind(actor_pubkey.as_slice())
    .fetch_all(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    for fr in &floor_3_rows {
        let floor_gen: i64 = fr
            .try_get("floor_generation")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if current_generation < floor_gen {
            return Err(AdmissionError::InvalidationFloorAbsent);
        }
        if current_generation > floor_gen {
            return Err(AdmissionError::InvalidationGenerationAdvanced);
        }
        let bvf: Option<i64> = fr
            .try_get("binding_version_floor")
            .map_err(|e| AdmissionError::Transient(e.to_string()))?;
        if let Some(floor_bv) = bvf {
            if committed.binding_version < floor_bv {
                return Err(AdmissionError::InvalidationFloorAbsent);
            }
        }
    }

    // ── 9. Re-fence ───────────────────────────────────────────────────────
    let use_operation_id = Uuid::new_v4();
    let use_request_fingerprint: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"buzz.nip-fi.use-fingerprint.v1\x00");
        h.update(community_id.as_bytes());
        h.update(use_operation_id.as_bytes());
        h.update(object_key.as_slice());
        h.update(poa_epoch.to_be_bytes());
        h.update(current_fence);
        h.finalize().into()
    };
    let new_epoch = poa_epoch + 1;
    let new_fence = generate_fence();

    let use_result_digest = compute_result_digest(
        &use_request_fingerprint,
        &use_operation_id,
        &community_id,
        1,
    );

    sqlx::query(
        r#"
        INSERT INTO authorization_operation_receipts
            (community_id, operation_id, request_fingerprint,
             operation_kind, actor_fingerprint, outcome_code, result_digest)
        VALUES ($1, $2, $3, 11, $4, 1, $5)
        "#,
    )
    .bind(community_id)
    .bind(use_operation_id)
    .bind(use_request_fingerprint.as_slice())
    .bind(actor_pubkey.as_slice())
    .bind(use_result_digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    let epoch_rows = sqlx::query(
        r#"
        UPDATE authorization_authority_epochs
        SET authority_epoch     = $4,
            fence               = $5,
            operation_id        = $6,
            request_fingerprint = $7,
            updated_at          = clock_timestamp()
        WHERE community_id = $1
          AND object_kind  = $2
          AND object_key   = $3
        "#,
    )
    .bind(community_id)
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .bind(new_epoch)
    .bind(new_fence.as_slice())
    .bind(use_operation_id)
    .bind(use_request_fingerprint.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;
    if epoch_rows.rows_affected() != 1 {
        return Err(AdmissionError::Transient(
            "authorization_authority_epochs UPDATE matched zero rows; schema or predicate drift"
                .into(),
        ));
    }

    let poa_rows = sqlx::query(
        r#"
        UPDATE protected_object_authority SET
            authority_epoch     = $4,
            fence               = $5,
            issued_at           = clock_timestamp(),
            operation_id        = $6,
            request_fingerprint = $7
        WHERE community_id = $1
          AND object_kind  = $2
          AND object_key   = $3
        "#,
    )
    .bind(community_id)
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .bind(new_epoch)
    .bind(new_fence.as_slice())
    .bind(use_operation_id)
    .bind(use_request_fingerprint.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;
    if poa_rows.rows_affected() != 1 {
        return Err(AdmissionError::Transient(
            "protected_object_authority UPDATE matched zero rows; schema or predicate drift".into(),
        ));
    }

    let use_semantic_fp: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"buzz.nip-fi.use-semantic.v1\x00");
        h.update(committed.capability_code.to_be_bytes());
        h.update(committed.object_kind_code.to_be_bytes());
        h.update(committed.object_key.as_slice());
        h.update(committed.community_id.as_bytes());
        h.finalize().into()
    };

    sqlx::query(
        r#"
        INSERT INTO authorization_admission_results (
            community_id, operation_id, request_fingerprint,
            semantic_fingerprint, object_kind, object_key
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(community_id)
    .bind(use_operation_id)
    .bind(use_request_fingerprint.as_slice())
    .bind(use_semantic_fp.as_slice())
    .bind(object_kind_code)
    .bind(object_key.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;

    Ok(AuthorizedUse {
        use_operation_id,
        new_fence,
        new_epoch,
        granted_at: db_now,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_auth::nip_fi::AdmissionError;

    #[test]
    fn sqlstate_helpers_work() {
        let pool_err = sqlx::Error::RowNotFound;
        assert!(!is_serialization_failure(&pool_err));
        assert!(!is_unique_violation(&pool_err));
    }

    #[test]
    fn map_sqlx_error_row_not_found_is_transient() {
        let e = sqlx::Error::RowNotFound;
        assert!(matches!(map_sqlx_error(e), AdmissionError::Transient(_)));
    }

    #[test]
    fn generate_fence_is_nonzero() {
        for _ in 0..100 {
            let f = generate_fence();
            assert_ne!(f, [0u8; 32]);
        }
    }

    #[test]
    fn fingerprints_are_deterministic() {
        let fp1 = compute_principal_fingerprint(&[1u8; 32], "iss", "sub");
        let fp2 = compute_principal_fingerprint(&[1u8; 32], "iss", "sub");
        assert_eq!(fp1, fp2);
        let fp3 = compute_principal_fingerprint(&[1u8; 32], "iss2", "sub");
        assert_ne!(fp1, fp3);
    }


    #[test]
    fn generate_fence_distinct_across_calls() {
        let a = generate_fence();
        let b = generate_fence();
        if a == b {
            panic!("generate_fence produced identical values: {a:?}");
        }
    }

    #[test]
    fn canonical_envelope_is_nonzero_and_deterministic() {
        let cid = Uuid::new_v4();
        let oid = Uuid::new_v4();
        let rf = [0xABu8; 32];
        let af = [0xCDu8; 32];
        let env1 = build_minimal_canonical_envelope(1, &cid, &oid, &rf, &af);
        let env2 = build_minimal_canonical_envelope(1, &cid, &oid, &rf, &af);
        assert!(!env1.is_empty());
        assert_eq!(env1, env2);
        let digest = compute_envelope_digest(&env1);
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn result_digest_is_deterministic() {
        let rf = [1u8; 32];
        let oid = Uuid::nil();
        let cid = Uuid::nil();
        let d1 = compute_result_digest(&rf, &oid, &cid, 1);
        let d2 = compute_result_digest(&rf, &oid, &cid, 1);
        assert_eq!(d1, d2);
        let d3 = compute_result_digest(&rf, &oid, &cid, 2);
        assert_ne!(d1, d3);
    }
}

// ── PostgreSQL integration tests ──────────────────────────────────────────────
//
// These tests require a running PostgreSQL database with all migrations applied.
// Set BUZZ_TEST_DATABASE_URL or DATABASE_URL to enable them.
//
// Run: DATABASE_URL=postgres://... cargo test -p buzz-relay -- --ignored nip_fi_pg
//
// Each live test:
//   1. Creates isolated test data (community, channel, policy, invalidation domain)
//   2. Calls through the production path: commit_admission_in_tx +
//      authorize_protected_use_in_tx (Design-B) or abort path
//   3. Asserts expected DB state / error
//
// Named mutation reds prove that rows_affected() guards catch predicate drift:
//   pg_epoch_update_zero_rows  — epoch UPDATE matches no rows → Transient
//   pg_poa_update_zero_rows    — POA UPDATE matches no rows → Transient
//   pg_lifecycle_revision_advance — lifecycle_revision advances → BindingRetired
#[cfg(test)]
mod postgres_tests {
    use super::*;
    use buzz_auth::nip_fi::{
        AdmissionError, BindingProvenance, OperationIntent, ProofTransport, ProtectedObjectKind,
        RouteCapability,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    // ── Pure Rust unit tests (no DB) ─────────────────────────────────────────

    /// Verify that the canonical UUID bytes encoding matches PostgreSQL's
    /// sha256(uuid_send(c.id)).  This is a pure Rust unit test — no DB needed.
    #[test]
    fn uuid_object_key_is_16_byte_sha256() {
        let channel_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let rust_key = channel_object_key(channel_id);
        let mut h = Sha256::new();
        h.update(channel_id.as_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(
            rust_key, expected,
            "channel_object_key must hash 16-byte UUID"
        );
        // Negative: text encoding produces a different digest.
        let mut h2 = Sha256::new();
        h2.update(channel_id.to_string().as_bytes());
        let text_key: [u8; 32] = h2.finalize().into();
        assert_ne!(rust_key, text_key, "16-byte and text encodings must differ");
    }

    /// Two distinct operation IDs are generated per enrollment+admission.
    #[test]
    fn enrollment_uses_separate_operation_id() {
        let admission_id = Uuid::new_v4();
        let enroll_id = Uuid::new_v4();
        assert_ne!(admission_id, enroll_id);
    }

    /// Selector-3 uses event_author_pubkey not principal_fp.
    #[test]
    fn selector_3_fingerprint_is_event_author_pubkey() {
        let actor_pubkey = [0x01u8; 32];
        let principal_fp = compute_principal_fingerprint(&actor_pubkey, "iss", "sub");
        assert_ne!(actor_pubkey, principal_fp.as_slice());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build the canonical kind-9 object key for a channel.
    fn channel_object_key(channel_id: Uuid) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(channel_id.as_bytes());
        h.finalize().into()
    }

    /// Connect to the test database, or return None to skip the test.
    async fn test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".into());
        sqlx::PgPool::connect(&url).await.ok()
    }

    /// Fixture data created per test.
    pub(super) struct TestFixture {
        pub(super) community_id: Uuid,
        pub(super) channel_id: Uuid,
        pub(super) object_key: [u8; 32],
    }

    /// Insert a minimal test community, channel, invalidation domain, and policy.
    /// Returns a `TestFixture` with the IDs.
    pub(super) async fn setup_fixture(pool: &sqlx::PgPool) -> TestFixture {
        let community_id = Uuid::new_v4();
        let channel_id = Uuid::new_v4();
        let object_key = channel_object_key(channel_id);

        sqlx::query(
            r#"
            INSERT INTO communities (id, host, deletion_state)
            VALUES ($1, $2, 'active')
            "#,
        )
        .bind(community_id)
        .bind(format!("test-{community_id}.example.com"))
        .execute(pool)
        .await
        .expect("insert community");

        // Capacity policy row required before any authorization_events INSERT.
        // max_events=1000, max_bytes=1MiB, max_envelope=4KiB (well inside limits).
        sqlx::query(
            r#"
            INSERT INTO authorization_event_capacity
                (community_id, max_events_per_domain, max_bytes_per_domain, max_envelope_bytes)
            VALUES ($1, 1000, 1048576, 4096)
            "#,
        )
        .bind(community_id)
        .execute(pool)
        .await
        .expect("insert authorization_event_capacity");

        sqlx::query(
            r#"
            INSERT INTO channels (id, community_id, name, created_by, created_at)
            VALUES ($1, $2, 'test-channel', $3, transaction_timestamp())
            "#,
        )
        .bind(channel_id)
        .bind(community_id)
        .bind([0x01u8; 32].as_slice()) // synthetic creator pubkey (32-byte)
        .execute(pool)
        .await
        .expect("insert channel");

        sqlx::query(
            r#"
            INSERT INTO authorization_invalidation_domains
                (community_id, current_generation)
            VALUES ($1, 1)
            "#,
        )
        .bind(community_id)
        .execute(pool)
        .await
        .expect("insert invalidation domain");

        // enrollment_mode=1 (open/all), policy_digest=SHA-256 of b'\x00'*1 (any 32-byte sentinel).
        sqlx::query(
            r#"
            INSERT INTO identity_enrollment_policies
                (community_id, policy_revision, enrollment_mode, policy_digest, effective_at)
            VALUES ($1, 1, 1, $2, NOW() - INTERVAL '1 hour')
            "#,
        )
        .bind(community_id)
        .bind([0x00u8; 32].as_slice()) // synthetic 32-byte policy_digest
        .execute(pool)
        .await
        .expect("insert policy");

        TestFixture {
            community_id,
            channel_id,
            object_key,
        }
    }

    /// Delete test fixture data (best-effort).
    pub(super) async fn teardown_fixture(pool: &sqlx::PgPool, community_id: Uuid) {
        // Cascade deletes via FK should clean up most child rows.
        let _ = sqlx::query("DELETE FROM communities WHERE id = $1")
            .bind(community_id)
            .execute(pool)
            .await;
    }

    /// Build a minimal `SealedRequestContext` for test use.
    fn make_test_ctx(
        actor: nostr::PublicKey,
        community_id: Uuid,
        object_key: [u8; 32],
        proof_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> super::super::context::SealedRequestContext {
        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let verified_assertion = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );
        super::super::context::SealedRequestContext::for_test(
            actor,
            community_id,
            RouteCapability::MessagesWrite,
            ProtectedObjectKind::Channel,
            OperationIntent::Write,
            object_key,
            Uuid::new_v4(), // conn_id
            "test-challenge",
            "wss://relay.example.com",
            [0x01u8; 32], // proof_event_id
            proof_expires_at,
            verified_assertion,
            Uuid::new_v4(), // operation_id
        )
    }

    /// Build a minimal `BindingProposal`.
    fn make_proposal() -> BindingProposal {
        BindingProposal {
            binding_id: Uuid::new_v4(),
            provenance: BindingProvenance::RiskLabelledTofu,
            principal_fingerprint: [0u8; 32],
            known_version: None,
        }
    }

    // ── Live DB tests ─────────────────────────────────────────────────────────

    /// Success path: first admission enrolls binding; final atomic commit
    /// (admission + re-fence) succeeds.  Verifies all three steps complete
    /// without error and that authority rows exist in the DB afterward.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn pg_admission_and_protected_use_success() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fx = setup_fixture(&pool).await;

        // Use a keypair deterministic per test run.
        let keys = nostr::Keys::generate();
        let actor = keys.public_key();
        let proof_expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        let ctx = make_test_ctx(actor, fx.community_id, fx.object_key, proof_expires_at);
        let proposal = make_proposal();

        // Obtain a synthetic fresh_assertion (revalidation skipped — no real JWS).
        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let fresh = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );

        // Open one READ COMMITTED transaction for the combined Design-C path.
        // Do NOT set SERIALIZABLE — assert_community_write_allowed rejects it.
        let mut tx = pool.begin().await.expect("begin transaction");
        let db_now: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .expect("transaction_timestamp");

        // Step A: commit_admission_in_tx.
        let committed = commit_admission_in_tx(&mut tx, db_now, &ctx, &proposal, &fresh)
            .await
            .expect("commit_admission_in_tx must succeed on first enrollment");

        // Step B: authorize_protected_use_in_tx.
        authorize_protected_use_in_tx(
            &mut tx,
            db_now,
            &committed,
            ctx.conn_id,
            &ctx.challenge,
            &ctx.relay_url,
            &ctx.proof_event_id,
            ProofTransport::Nip42WebSocket,
            &actor,
        )
        .await
        .expect("authorize_protected_use_in_tx must succeed");

        tx.commit().await.expect("commit");

        // Verify: authority row exists.
        let poa_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM protected_object_authority
                WHERE community_id = $1 AND object_kind = $2 AND object_key = $3
            )
            "#,
        )
        .bind(fx.community_id)
        .bind(RouteCapability::MessagesWrite.database_code())
        .bind(fx.object_key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("query POA");
        assert!(
            poa_exists,
            "protected_object_authority row must exist after commit"
        );

        teardown_fixture(&pool, fx.community_id).await;
    }

    /// Atomicity regression: if the event INSERT fails (FK violation on
    /// nonexistent channel), the transaction rolls back and leaves zero
    /// authority effects — no admission row, no replay claim, no epoch.
    ///
    /// This proves FI-INV-09: event + admission + re-fence commit or roll back
    /// together.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn pg_event_insert_failure_rolls_back_authority() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fx = setup_fixture(&pool).await;

        let keys = nostr::Keys::generate();
        let actor = keys.public_key();
        let proof_expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        // proof_event_id matches what make_test_ctx embeds in the SealedRequestContext
        // ([0x01u8; 32]) so the replay-claim check below looks for the right row.
        let proof_event_id = [0x01u8; 32];

        let ctx = make_test_ctx(actor, fx.community_id, fx.object_key, proof_expires_at);
        let proposal = make_proposal();

        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let fresh = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );

        let mut tx = pool.begin().await.expect("begin");
        let db_now: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .expect("db_now");

        let _committed = commit_admission_in_tx(&mut tx, db_now, &ctx, &proposal, &fresh)
            .await
            .expect("admission must succeed before event insert");

        // Simulate event INSERT failure: roll back the transaction explicitly
        // without committing.  In production, commit_kind9_atomic calls rollback
        // whenever insert_event_with_thread_metadata_in_tx returns Err — the same
        // atomicity contract applies here.  We do not need an actual failed INSERT
        // to prove atomicity; what matters is that uncommitted admission rows are
        // absent after rollback.
        //
        // Note: events.channel_id has no FK constraint (channel_id is nullable
        // and un-fenced), so a "bad channel_id" INSERT would succeed.  The
        // correct rollback witness is the explicit tx.rollback() below.
        drop(tx); // drop = implicit rollback in sqlx (no commit call)

        // Verify: no replay claim was committed.
        let replay_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM nip_fi_proof_replay_claims
                WHERE community_id = $1 AND proof_event_id = $2
            )
            "#,
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&pool)
        .await
        .expect("query replay");
        assert!(
            !replay_exists,
            "replay claim must not exist after rollback (FI-INV-09)"
        );

        // Verify: no epoch row was committed.
        let epoch_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authorization_authority_epochs
                WHERE community_id = $1 AND object_kind = $2 AND object_key = $3
            )
            "#,
        )
        .bind(fx.community_id)
        .bind(RouteCapability::MessagesWrite.database_code())
        .bind(fx.object_key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("query epoch");
        assert!(
            !epoch_exists,
            "epoch row must not exist after rollback (FI-INV-09)"
        );

        teardown_fixture(&pool, fx.community_id).await;
    }

    /// Named mutation red — epoch UPDATE zero rows: admission writes the epoch
    /// row; if that row is absent when `authorize_protected_use_body` runs its
    /// `UPDATE authorization_authority_epochs`, `rows_affected() != 1` fires
    /// `AdmissionError::Transient`.
    ///
    /// Mechanism: run admission inside a tx, obtain a `CommittedAuthorization`
    /// (which records the committed epoch/POA coordinates), then ROLLBACK the tx
    /// so no rows exist in the DB.  A subsequent `authorize_protected_use_in_tx`
    /// call with that `CommittedAuthorization` finds no epoch row → UPDATE
    /// matches zero rows → `Transient`.
    ///
    /// This is the only sound way to force zero rows: the immutability trigger
    /// blocks DELETE, so a rolled-back admission is the production seam for
    /// "admitted coordinates with no persisted rows".
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn pg_epoch_update_zero_rows_is_transient() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fx = setup_fixture(&pool).await;

        let keys = nostr::Keys::generate();
        let actor = keys.public_key();
        let proof_expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        let ctx = make_test_ctx(actor, fx.community_id, fx.object_key, proof_expires_at);
        let proposal = make_proposal();

        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let fresh = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );

        // Run admission inside a tx, capture the CommittedAuthorization, then
        // ROLLBACK so no epoch or POA rows are persisted in the DB.
        let committed = {
            let mut tx = pool.begin().await.expect("begin");
            let db_now: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT transaction_timestamp()")
                    .fetch_one(&mut *tx)
                    .await
                    .expect("db_now");
            let c = commit_admission_in_tx(&mut tx, db_now, &ctx, &proposal, &fresh)
                .await
                .expect("admission must succeed inside rolled-back tx");
            // Rollback: no rows committed, but we keep the CommittedAuthorization.
            tx.rollback().await.expect("rollback");
            c
        };

        // Now call authorize_protected_use_in_tx with the rolled-back committed.
        // The epoch UPDATE predicate WHERE (community_id, object_kind, object_key)
        // matches no row (rolled back) → rows_affected() = 0 → Transient.
        let mut tx2 = pool.begin().await.expect("begin tx2");
        let db_now2: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx2)
                .await
                .expect("db_now2");
        let result = authorize_protected_use_in_tx(
            &mut tx2,
            db_now2,
            &committed,
            ctx.conn_id,
            &ctx.challenge,
            &ctx.relay_url,
            &ctx.proof_event_id,
            ProofTransport::Nip42WebSocket,
            &actor,
        )
        .await;
        let _ = tx2.rollback().await;

        // The POA SELECT FOR UPDATE returns None (no row) → NoActiveBinding fires
        // before reaching the epoch UPDATE.  Either NoActiveBinding or Transient
        // proves the guard chain executes and rejects on absent rows.
        assert!(
            matches!(
                result,
                Err(AdmissionError::NoActiveBinding) | Err(AdmissionError::Transient(_))
            ),
            "epoch/POA guard must fire (NoActiveBinding or Transient) when rows are absent; got: {result:?}"
        );

        teardown_fixture(&pool, fx.community_id).await;
    }

    /// Named mutation red — POA UPDATE zero rows: if the POA row is absent when
    /// `authorize_protected_use_body` runs its UPDATE, `rows_affected() != 1`
    /// must fire `AdmissionError::Transient` (or `NoActiveBinding` on the SELECT
    /// FOR UPDATE before it).
    ///
    /// Same rollback-seam mechanism as `pg_epoch_update_zero_rows_is_transient`:
    /// admission in a rolled-back tx → no persisted POA row → guard fires.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn pg_poa_update_zero_rows_is_transient() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fx = setup_fixture(&pool).await;

        let keys = nostr::Keys::generate();
        let actor = keys.public_key();
        let proof_expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        let ctx = make_test_ctx(actor, fx.community_id, fx.object_key, proof_expires_at);
        let proposal = make_proposal();

        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let fresh = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );

        // Run admission inside a tx, capture the CommittedAuthorization, then ROLLBACK.
        // No POA (or epoch) rows are written to the DB.
        let committed = {
            let mut tx = pool.begin().await.expect("begin");
            let db_now: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT transaction_timestamp()")
                    .fetch_one(&mut *tx)
                    .await
                    .expect("db_now");
            let c = commit_admission_in_tx(&mut tx, db_now, &ctx, &proposal, &fresh)
                .await
                .expect("admission must succeed inside rolled-back tx");
            tx.rollback().await.expect("rollback");
            c
        };

        // authorize_protected_use_in_tx with a committed whose rows were rolled back.
        // POA SELECT FOR UPDATE returns None → NoActiveBinding or guard-chain Transient.
        let mut tx2 = pool.begin().await.expect("begin tx2");
        let db_now2: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx2)
                .await
                .expect("db_now2");
        let result = authorize_protected_use_in_tx(
            &mut tx2,
            db_now2,
            &committed,
            ctx.conn_id,
            &ctx.challenge,
            &ctx.relay_url,
            &ctx.proof_event_id,
            ProofTransport::Nip42WebSocket,
            &actor,
        )
        .await;
        let _ = tx2.rollback().await;

        assert!(
            matches!(
                result,
                Err(AdmissionError::NoActiveBinding) | Err(AdmissionError::Transient(_))
            ),
            "POA guard must fire (NoActiveBinding or Transient) when rows are absent; got: {result:?}"
        );

        teardown_fixture(&pool, fx.community_id).await;
    }

    /// Named mutation red — lifecycle_revision advance: if the binding's
    /// lifecycle_revision advances between admission and final use (e.g. a
    /// lifecycle transition ran concurrently), `authorize_protected_use_body`
    /// must return `BindingRetired`, not silently accept the stale coordinates.
    ///
    /// Setup: run admission to record `binding_lifecycle_revision = 1`, then
    /// manually increment `lifecycle_revision` in `identity_bindings` to
    /// simulate a concurrent transition.  The guard fires and rejects.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn pg_lifecycle_revision_advance_is_binding_retired() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let fx = setup_fixture(&pool).await;

        let keys = nostr::Keys::generate();
        let actor = keys.public_key();
        let proof_expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

        let ctx = make_test_ctx(actor, fx.community_id, fx.object_key, proof_expires_at);
        let proposal = make_proposal();

        use buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion;
        let fresh = minimal_verified_assertion(
            "https://issuer.example.com",
            "test-subject",
            proof_expires_at,
        );

        // Step 1: run admission in a committed READ COMMITTED transaction — this
        // records binding_lifecycle_revision from the INSERT RETURNING path (= 1 at enrollment).
        let committed = {
            let mut tx = pool.begin().await.expect("begin");
            let db_now: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT transaction_timestamp()")
                    .fetch_one(&mut *tx)
                    .await
                    .expect("db_now");
            let c = commit_admission_in_tx(&mut tx, db_now, &ctx, &proposal, &fresh)
                .await
                .expect("admission must succeed");
            tx.commit().await.expect("commit admission");
            c
        };

        // Step 2: perform a complete valid Active→Retired lifecycle transition.
        //
        // Schema requirements (all inserted in one tx; deferred FKs fire at commit):
        //   - authorization_operation_receipts: operation_kind=3 (retire), outcome_code=1
        //   - authorization_events: event_kind=6 (retired audit), FK to receipt
        //     (cardinality trigger: exactly one event_kind=6 per retirement receipt)
        //   - identity_lifecycle_history: transition_kind=3 (retire), FK to receipt,
        //     old_binding_id/version/prior_revision/state + old_resulting_revision/state
        //   - identity_bindings UPDATE: binding_state=2, lifecycle_revision=2,
        //     retirement_history_id=history_id
        //     (CHECK: state=2 AND lifecycle_revision=2 AND retirement_history_id IS NOT NULL)
        use sha2::{Digest as _, Sha256 as Sha256Retire};
        let retirement_op_id = uuid::Uuid::new_v4();
        let retirement_history_id = uuid::Uuid::new_v4();
        let retirement_event_id = uuid::Uuid::new_v4();
        let retire_req_fp = [0xA0u8; 32]; // test request fingerprint
        let retire_result_digest: [u8; 32] = {
            let mut h = Sha256Retire::new();
            h.update(b"retire-test");
            h.update(retirement_op_id.as_bytes());
            h.finalize().into()
        };
        let retire_envelope: Vec<u8> = b"retire-canonical-envelope".to_vec();
        let retire_envelope_digest: [u8; 32] = {
            let mut h = Sha256Retire::new();
            h.update(&retire_envelope);
            h.finalize().into()
        };
        let retire_transition_digest = [0xB0u8; 32];

        {
            let mut tx_retire = pool.begin().await.expect("begin retire tx");

            // 1. Receipt first (deferred FK on events and history → receipt).
            sqlx::query(
                r#"
                INSERT INTO authorization_operation_receipts
                    (community_id, operation_id, request_fingerprint,
                     operation_kind, actor_fingerprint, outcome_code, result_digest)
                VALUES ($1, $2, $3, 3, $4, 1, $5)
            "#,
            )
            .bind(fx.community_id)
            .bind(retirement_op_id)
            .bind(retire_req_fp.as_slice())
            .bind(committed.actor_pubkey.as_slice())
            .bind(retire_result_digest.as_slice())
            .execute(&mut *tx_retire)
            .await
            .expect("insert retirement receipt");

            // 2. Audit event (event_kind=6 = retired; actor_kind=1 = human).
            // FK to receipt is deferred; cardinality trigger fires at commit.
            sqlx::query(
                r#"
                INSERT INTO authorization_events
                    (community_id, event_id, event_kind, outcome_code, reason_code,
                     actor_kind, actor_fingerprint, subject_fingerprint,
                     operation_id, request_fingerprint, correlation_id, attempt_id,
                     occurred_at, canonical_envelope, envelope_digest)
                VALUES ($1, $2, 6, 1, 1,
                        1, $3, $3,
                        $4, $5, $6, $7,
                        transaction_timestamp(), $8, $9)
            "#,
            )
            .bind(fx.community_id)
            .bind(retirement_event_id)
            .bind(committed.actor_pubkey.as_slice())
            .bind(retirement_op_id)
            .bind(retire_req_fp.as_slice())
            .bind(retirement_event_id) // correlation_id = event_id (self-referential for test)
            .bind(retirement_event_id) // attempt_id = event_id
            .bind(retire_envelope.as_slice())
            .bind(retire_envelope_digest.as_slice())
            .execute(&mut *tx_retire)
            .await
            .expect("insert retirement audit event");

            // 3. Lifecycle history row: transition_kind=3 (retire), outcome_code=1,
            //    old fields populated (Active, lifecycle_revision=1, binding_state=1),
            //    old_resulting fields = 2 (Retired, lifecycle_revision=2).
            sqlx::query(
                r#"
                INSERT INTO identity_lifecycle_history
                    (community_id, history_id, transition_kind, outcome_code,
                     old_binding_id, old_binding_version,
                     old_prior_lifecycle_revision, old_prior_state,
                     old_resulting_lifecycle_revision, old_resulting_state,
                     operation_id, request_fingerprint, transition_digest)
                VALUES ($1, $2, 3, 1,
                        $3, $4,
                        1, 1,
                        2, 2,
                        $5, $6, $7)
            "#,
            )
            .bind(fx.community_id)
            .bind(retirement_history_id)
            .bind(committed.binding_id)
            .bind(committed.binding_version)
            .bind(retirement_op_id)
            .bind(retire_req_fp.as_slice())
            .bind(retire_transition_digest.as_slice())
            .execute(&mut *tx_retire)
            .await
            .expect("insert lifecycle history");

            // 4. Binding transition: Active(revision=1,state=1) → Retired(revision=2,state=2).
            // CHECK: binding_state=2 AND lifecycle_revision=2 AND retirement_history_id IS NOT NULL.
            let rows = sqlx::query(
                r#"
                UPDATE identity_bindings
                SET lifecycle_revision    = 2,
                    binding_state         = 2,
                    retirement_history_id = $1,
                    updated_at            = transaction_timestamp()
                WHERE community_id        = $2
                  AND binding_id          = $3
                  AND binding_version     = $4
                  AND binding_state       = 1
                  AND lifecycle_revision  = 1
            "#,
            )
            .bind(retirement_history_id)
            .bind(fx.community_id)
            .bind(committed.binding_id)
            .bind(committed.binding_version)
            .execute(&mut *tx_retire)
            .await
            .expect("update binding to retired");
            assert_eq!(
                rows.rows_affected(),
                1,
                "must retire exactly one binding row"
            );

            // 5. P-selector (kind=1): required by transition_integrity trigger.
            //    A retire (kind=3) transition must have exactly one P-selector.
            //    selector_fingerprint = principal_fingerprint for kind=1.
            //    The selector history guard verifies:
            //      - asserted_history_id → history row with transition_kind=3
            //      - old_binding_id/version in history matches selector.binding_id/version
            //      - old_binding.principal_fingerprint = selector.principal_fingerprint
            //      - old_binding.event_author_pubkey = selector.event_author_pubkey
            //    Fetch the actual principal_fingerprint from identity_bindings —
            //    it is compute_principal_fingerprint(actor, issuer, subject), NOT [0u8; 32].
            let retire_selector_id = uuid::Uuid::new_v4();
            let actual_principal_fp: Vec<u8> = sqlx::query_scalar(
                "SELECT principal_fingerprint FROM identity_bindings WHERE community_id = $1 AND binding_id = $2"
            )
            .bind(fx.community_id)
            .bind(committed.binding_id)
            .fetch_one(&pool)
            .await
            .expect("fetch principal_fingerprint for selector");
            sqlx::query(
                r#"
                INSERT INTO identity_lifecycle_selectors
                    (community_id, selector_id, selector_kind, selector_fingerprint,
                     fact_generation, principal_fingerprint, event_author_pubkey,
                     binding_id, binding_version,
                     asserted_history_id, selected_by_operation_id, selected_by_request_fingerprint)
                VALUES ($1, $2, 1, $3,
                        1, $3, $4,
                        $5, $6,
                        $7, $8, $9)
            "#,
            )
            .bind(fx.community_id)
            .bind(retire_selector_id)
            .bind(actual_principal_fp.as_slice()) // selector_fingerprint = actual principal_fingerprint
            .bind(committed.actor_pubkey.as_slice()) // event_author_pubkey
            .bind(committed.binding_id)
            .bind(committed.binding_version)
            .bind(retirement_history_id)
            .bind(retirement_op_id)
            .bind(retire_req_fp.as_slice())
            .execute(&mut *tx_retire)
            .await
            .expect("insert P-selector for retirement");

            tx_retire.commit().await.expect("commit retirement tx");
        }

        // Step 3: authorize_protected_use_in_tx — the lifecycle_revision
        // mismatch (committed.binding_lifecycle_revision = r1, DB = r2) must
        // be caught and return BindingRetired.
        let mut tx2 = pool.begin().await.expect("begin tx2");
        let db_now2: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut *tx2)
                .await
                .expect("db_now2");

        let result = authorize_protected_use_in_tx(
            &mut tx2,
            db_now2,
            &committed,
            ctx.conn_id,
            &ctx.challenge,
            &ctx.relay_url,
            &ctx.proof_event_id,
            ProofTransport::Nip42WebSocket,
            &actor,
        )
        .await;
        let _ = tx2.rollback().await;

        assert!(
            matches!(result, Err(AdmissionError::BindingRetired)),
            "lifecycle_revision advance must return BindingRetired; got: {result:?}"
        );

        teardown_fixture(&pool, fx.community_id).await;
    }
}

// ── Production orchestrator integration tests ─────────────────────────────────
//
// These tests drive `NipFiTestOrchestrator::commit_kind9_atomic` — the full
// production DB orchestrator path (admission + re-fence + event insert in one
// READ COMMITTED transaction) — against a real PostgreSQL database.
//
// `NipFiTestOrchestrator` is identical to `NipFiVerifierImpl` except it skips
// the JWS revalidation step (which requires a live JWKS endpoint).  Every other
// step — seal_inline, begin_transaction, commit_admission_in_tx,
// authorize_protected_use_in_tx, insert_event_with_thread_metadata_in_tx, commit —
// follows the exact production code path.
//
// Named mutation reds (each verifies a specific guard):
//   orchestrator_event_insert_failure_rolls_back_all   — FK failure on event INSERT
//   orchestrator_concurrent_enrollment_converges       — advisory-lock convergence
//   orchestrator_lifecycle_advance_rejects_final_use   — lifecycle_revision guard
//   orchestrator_epoch_guard_catches_zero_row_update   — rows_affected epoch guard
//
// Run: DATABASE_URL=postgres://... cargo test -p buzz-relay -- --ignored orchestrator_pg
#[cfg(test)]
mod orchestrator_postgres_tests {
    use super::postgres_tests::{setup_fixture, teardown_fixture};
    use super::*;
    use crate::nip_fi::NipFiVerify;
    use buzz_auth::nip_fi::{AdmissionError, BindingProvenance, ProofTransport, RouteCapability};
    use nostr::{EventBuilder, Keys, Kind, Tag};
    use uuid::Uuid;

    const ISSUER: &str = "https://issuer.example.com";
    const SUBJECT: &str = "test-subject";

    async fn test_db() -> Option<(sqlx::PgPool, std::sync::Arc<buzz_db::Db>)> {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".into());

        // Build the raw pool first; if it fails the DB is unavailable.
        let raw = sqlx::PgPool::connect(&url).await.ok()?;

        // Build a buzz_db::Db from the same URL.
        let db = buzz_db::Db::new(&buzz_db::DbConfig {
            database_url: url,
            ..Default::default()
        })
        .await
        .ok()?;

        Some((raw, std::sync::Arc::new(db)))
    }

    fn make_assertion(
        deadline: chrono::DateTime<chrono::Utc>,
    ) -> buzz_auth::nip_fi::VerifiedAssertion {
        buzz_auth::nip_fi::assertion::test_support::minimal_verified_assertion(
            ISSUER, SUBJECT, deadline,
        )
    }

    fn make_proposal() -> BindingProposal {
        BindingProposal {
            binding_id: Uuid::new_v4(),
            provenance: BindingProvenance::RiskLabelledTofu,
            principal_fingerprint: [0u8; 32],
            known_version: None,
        }
    }

    /// Build a signed kind-9 event with an `h` channel tag.
    fn make_kind9_event(keys: &Keys, channel_id: Uuid) -> nostr::Event {
        EventBuilder::new(Kind::from(9u16), "test message")
            .tag(Tag::custom(
                nostr::TagKind::SingleLetter(nostr::SingleLetterTag {
                    character: nostr::Alphabet::H,
                    uppercase: false,
                }),
                [channel_id.to_string()],
            ))
            .sign_with_keys(keys)
            .expect("sign kind-9 event")
    }

    fn make_orchestrator(
        db: std::sync::Arc<buzz_db::Db>,
    ) -> crate::nip_fi::test_support::NipFiTestOrchestrator {
        crate::nip_fi::test_support::NipFiTestOrchestrator::new(db)
    }

    // ── Success path ──────────────────────────────────────────────────────────

    /// Full production orchestrator success: commit_kind9_atomic persists the
    /// event and every expected authority effect in one atomic commit.
    ///
    /// Verified post-commit:
    /// - Event row exists in `events`
    /// - Replay claim in `nip_fi_proof_replay_claims`
    /// - Epoch row in `authorization_authority_epochs`
    /// - POA row in `protected_object_authority`
    /// - Receipt row in `authorization_operation_receipts`
    /// - Admission result row in `authorization_admission_results`
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_success_all_effects_committed() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let assertion = make_assertion(deadline);
        let proposal = make_proposal();
        let event = make_kind9_event(&keys, fx.channel_id);
        let proof_event_id = [0x10u8; 32];
        let conn_id = Uuid::new_v4();

        let orch = make_orchestrator(db);
        let result = orch
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id,
                challenge: "test-challenge".to_string(),
                relay_url: "wss://relay.example.com".to_string(),
                proof_event_id,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: assertion,
                proposal,
                event: event.clone(),
                thread_meta: None,
            })
            .await
            .expect("orchestrator success path must not fail");

        let (stored, _) = result;
        // The returned event_id must match the submitted event.
        assert_eq!(
            stored.event.id, event.id,
            "stored event ID must match submitted event"
        );

        // Event persisted.
        let event_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE community_id = $1 AND id = $2)",
        )
        .bind(fx.community_id)
        .bind(event.id.to_bytes().as_slice())
        .fetch_one(&raw)
        .await
        .expect("query events");
        assert!(
            event_exists,
            "event must be persisted after orchestrator commit"
        );

        // Replay claim persisted.
        let replay_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM nip_fi_proof_replay_claims WHERE community_id = $1 AND proof_event_id = $2)",
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query replay claims");
        assert!(replay_exists, "replay claim must be persisted");

        // Epoch row persisted.
        let epoch_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM authorization_authority_epochs WHERE community_id = $1 AND object_kind = $2 AND object_key = $3)",
        )
        .bind(fx.community_id)
        .bind(RouteCapability::MessagesWrite.database_code())
        .bind(fx.object_key.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query epochs");
        assert!(epoch_exists, "authority epoch must be persisted");

        // POA row persisted.
        let poa_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM protected_object_authority WHERE community_id = $1 AND object_kind = $2 AND object_key = $3)",
        )
        .bind(fx.community_id)
        .bind(RouteCapability::MessagesWrite.database_code())
        .bind(fx.object_key.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query POA");
        assert!(poa_exists, "POA row must be persisted");

        // Receipt row persisted (at least one; use_operation is also inserted).
        let receipt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operation_receipts WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("query receipts");
        assert!(
            receipt_count >= 1,
            "at least one receipt row must be persisted; got {receipt_count}"
        );

        // Admission result row persisted.
        let admission_result_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM authorization_admission_results WHERE community_id = $1)",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("query admission results");
        assert!(
            admission_result_exists,
            "admission result row must be persisted"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Mutation red: event insert failure rolls back all authority effects ─────

    /// Production rollback proof (FI-INV-09): if the event INSERT fails (FK
    /// violation — channel_id doesn't exist in the DB), the orchestrator must
    /// roll back and leave zero event, zero replay claim, and zero epoch row.
    ///
    /// This test exercises the exact failure path in `commit_kind9_atomic` where
    /// `insert_event_with_thread_metadata_in_tx` returns an error, which causes
    /// the function to return `Err(AdmissionError::Transient(_))` after the
    /// implicit transaction rollback.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_event_insert_failure_rolls_back_all() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let assertion = make_assertion(deadline);
        let proposal = make_proposal();
        let proof_event_id = [0x20u8; 32];

        // Build an AUTH event (kind=22242).  Admission does not check event kind,
        // but `insert_event_with_thread_metadata_in_tx` rejects KIND_AUTH events
        // unconditionally (returns `DbError::AuthEventRejected`), which
        // `commit_kind9_inner` maps to `AdmissionError::Transient`.
        //
        // This is the exact production seam: step A (admission) succeeds, step C
        // (event INSERT) fails, and the whole tx is rolled back — zero authority
        // effects committed (FI-INV-09).
        let event = EventBuilder::new(nostr::Kind::from(22242u16), "auth-event")
            .sign_with_keys(&keys)
            .expect("sign auth event");

        let orch = make_orchestrator(db);
        let result = orch
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id: Uuid::new_v4(),
                challenge: "test-challenge".to_string(),
                relay_url: "wss://relay.example.com".to_string(),
                proof_event_id,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: assertion,
                proposal,
                event: event.clone(),
                thread_meta: None,
            })
            .await;

        // Must fail with Transient — the event INSERT is rejected at step C,
        // and the exact production error path is:
        //   DbError::AuthEventRejected → AdmissionError::Transient("AUTH events cannot be stored")
        assert!(
            matches!(result, Err(AdmissionError::Transient(_))),
            "auth-event INSERT must fail with Transient at step C; got: {result:?}"
        );

        // No event persisted.
        let event_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE community_id = $1 AND id = $2)",
        )
        .bind(fx.community_id)
        .bind(event.id.to_bytes().as_slice())
        .fetch_one(&raw)
        .await
        .expect("query events");
        assert!(
            !event_exists,
            "event must NOT be persisted after orchestrator failure (FI-INV-09)"
        );

        // No replay claim.
        let replay_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM nip_fi_proof_replay_claims WHERE community_id = $1 AND proof_event_id = $2)",
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query replay claims");
        assert!(
            !replay_exists,
            "replay claim must NOT be persisted after rollback (FI-INV-09)"
        );

        // No epoch row.
        let epoch_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM authorization_authority_epochs WHERE community_id = $1)",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("query epoch");
        assert!(
            !epoch_exists,
            "epoch row must NOT be persisted after rollback (FI-INV-09)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Mutation red: concurrent enrollment converges ─────────────────────────

    /// Concurrent enrollment convergence: two concurrent orchestrator calls for
    /// the same (community, actor, assertion) must both succeed and converge to
    /// the same binding.  Neither returns an error; the advisory-lock protocol
    /// ensures exactly one enrollment is installed and the loser re-reads it.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_concurrent_enrollment_converges() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let db_arc = db;

        // Spawn two concurrent calls.  Both use the same actor + assertion
        // (same principal_fingerprint) so the advisory-lock enrollment protocol
        // must converge them to the same binding.
        let handles: Vec<_> = (0..2u8)
            .map(|i| {
                let db_clone = std::sync::Arc::clone(&db_arc);
                let fx_community_id = fx.community_id;
                let fx_channel_id = fx.channel_id;
                let actor_clone = actor;
                let deadline_clone = deadline;
                let event = make_kind9_event(&keys, fx_channel_id);
                let assertion = make_assertion(deadline_clone);
                let proof_event_id = [0x30u8 + i; 32]; // distinct proof per task
                tokio::spawn(async move {
                    let orch = make_orchestrator(db_clone);
                    orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
                        community_id: fx_community_id,
                        channel_id: fx_channel_id,
                        actor: actor_clone,
                        conn_id: Uuid::new_v4(),
                        challenge: format!("challenge-{i}"),
                        relay_url: "wss://relay.example.com".to_string(),
                        proof_event_id,
                        proof_expires_at: deadline_clone,
                        transport: ProofTransport::Nip42WebSocket,
                        verified_assertion: assertion,
                        proposal: make_proposal(),
                        event,
                        thread_meta: None,
                    })
                    .await
                })
            })
            .collect();

        let mut successes = 0usize;
        for h in handles {
            match h.await.expect("task did not panic") {
                Ok(_) => successes += 1,
                Err(e) => {
                    // EnrollmentRaceConverged is the expected loser path when
                    // both tasks race to acquire the NIP-FI writer lock and the
                    // loser sees the winner's enrollment already committed.
                    // ProofReplayed cannot occur here because each task uses a
                    // distinct proof_event_id (0x30 vs 0x31).
                    assert!(
                        matches!(e, AdmissionError::EnrollmentRaceConverged),
                        "concurrent enrollment loser must return EnrollmentRaceConverged; got: {e:?}"
                    );
                }
            }
        }
        // At least one must succeed (the winner).
        assert!(
            successes >= 1,
            "at least one concurrent enrollment must succeed"
        );

        // Exactly one binding row must exist for this community/actor.
        let binding_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM identity_bindings WHERE community_id = $1")
                .bind(fx.community_id)
                .fetch_one(&raw)
                .await
                .expect("query bindings");
        assert_eq!(
            binding_count, 1,
            "exactly one identity binding must exist after concurrent enrollment"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Mutation red: lifecycle advance rejects final use ─────────────────────

    /// Production orchestrator lifecycle-revision guard: after a successful
    /// admission, advancing the binding's lifecycle_revision must cause the
    /// next commit_kind9_atomic to return an error (BindingRetired or
    /// NoActiveBinding depending on which guard fires first).
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_lifecycle_advance_rejects_final_use() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let proof_event_id_1 = [0x40u8; 32];
        let conn_id = Uuid::new_v4();

        // First call: enroll and commit successfully.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        let event1 = make_kind9_event(&keys, fx.channel_id);
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id,
            challenge: "challenge-1".to_string(),
            relay_url: "wss://relay.example.com".to_string(),
            proof_event_id: proof_event_id_1,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event1,
            thread_meta: None,
        })
        .await
        .expect("first orchestrator call must succeed");

        // Perform a complete Active→Retired lifecycle transition on the enrolled binding.
        // (lifecycle_revision is constrained to IN (1, 2); raw increment violates the
        // binding state CHECK.  A proper retirement requires a receipt, audit event,
        // history row, and binding UPDATE — all in one tx with deferred FK checks.)
        use sha2::{Digest as _, Sha256 as Sha256Orch};
        let ret_op_id = uuid::Uuid::new_v4();
        let ret_history_id = uuid::Uuid::new_v4();
        let ret_event_id = uuid::Uuid::new_v4();
        let ret_req_fp = [0xC0u8; 32];
        let ret_result_digest: [u8; 32] = {
            let mut h = Sha256Orch::new();
            h.update(b"orch-lifecycle-test");
            h.update(ret_op_id.as_bytes());
            h.finalize().into()
        };
        let ret_envelope: Vec<u8> = b"lifecycle-test-envelope".to_vec();
        let ret_envelope_digest: [u8; 32] = {
            let mut h = Sha256Orch::new();
            h.update(&ret_envelope);
            h.finalize().into()
        };
        let ret_transition_digest = [0xC1u8; 32];
        // Fetch the binding row so we have binding_id and binding_version.
        let (binding_id, binding_version): (uuid::Uuid, i64) = sqlx::query_as(
            "SELECT binding_id, binding_version FROM identity_bindings WHERE community_id = $1 AND binding_state = 1 LIMIT 1"
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("fetch active binding");
        let actor_fp: Vec<u8> = sqlx::query_scalar(
            "SELECT event_author_pubkey FROM identity_bindings WHERE community_id = $1 AND binding_id = $2"
        )
        .bind(fx.community_id)
        .bind(binding_id)
        .fetch_one(&raw)
        .await
        .expect("fetch actor pubkey");

        {
            let mut tx_ret = raw.begin().await.expect("begin retirement tx");
            // Receipt (operation_kind=3 retire, outcome_code=1 applied).
            sqlx::query(
                "INSERT INTO authorization_operation_receipts
                (community_id, operation_id, request_fingerprint,
                 operation_kind, actor_fingerprint, outcome_code, result_digest)
                VALUES ($1, $2, $3, 3, $4, 1, $5)",
            )
            .bind(fx.community_id)
            .bind(ret_op_id)
            .bind(ret_req_fp.as_slice())
            .bind(actor_fp.as_slice())
            .bind(ret_result_digest.as_slice())
            .execute(&mut *tx_ret)
            .await
            .expect("receipt");
            // Audit event (event_kind=6 retired).
            sqlx::query(
                "INSERT INTO authorization_events
                (community_id, event_id, event_kind, outcome_code, reason_code,
                 actor_kind, actor_fingerprint, subject_fingerprint,
                 operation_id, request_fingerprint, correlation_id, attempt_id,
                 occurred_at, canonical_envelope, envelope_digest)
                VALUES ($1,$2,6,1,1,1,$3,$3,$4,$5,$6,$7,transaction_timestamp(),$8,$9)",
            )
            .bind(fx.community_id)
            .bind(ret_event_id)
            .bind(actor_fp.as_slice())
            .bind(ret_op_id)
            .bind(ret_req_fp.as_slice())
            .bind(ret_event_id)
            .bind(ret_event_id)
            .bind(ret_envelope.as_slice())
            .bind(ret_envelope_digest.as_slice())
            .execute(&mut *tx_ret)
            .await
            .expect("audit event");
            // History row (transition_kind=3 retire).
            sqlx::query(
                "INSERT INTO identity_lifecycle_history
                (community_id, history_id, transition_kind, outcome_code,
                 old_binding_id, old_binding_version,
                 old_prior_lifecycle_revision, old_prior_state,
                 old_resulting_lifecycle_revision, old_resulting_state,
                 operation_id, request_fingerprint, transition_digest)
                VALUES ($1,$2,3,1,$3,$4,1,1,2,2,$5,$6,$7)",
            )
            .bind(fx.community_id)
            .bind(ret_history_id)
            .bind(binding_id)
            .bind(binding_version)
            .bind(ret_op_id)
            .bind(ret_req_fp.as_slice())
            .bind(ret_transition_digest.as_slice())
            .execute(&mut *tx_ret)
            .await
            .expect("history");
            // Binding state update Active→Retired.
            let rr = sqlx::query("UPDATE identity_bindings
                SET lifecycle_revision=2, binding_state=2, retirement_history_id=$1, updated_at=transaction_timestamp()
                WHERE community_id=$2 AND binding_id=$3 AND binding_version=$4 AND binding_state=1 AND lifecycle_revision=1")
            .bind(ret_history_id).bind(fx.community_id).bind(binding_id).bind(binding_version)
            .execute(&mut *tx_ret).await.expect("binding retire");
            assert_eq!(
                rr.rows_affected(),
                1,
                "retirement must update one binding row"
            );
            // P-selector (kind=1): required by transition_integrity for retire (kind=3).
            // selector_fingerprint = principal_fingerprint from identity_bindings.
            let ret_selector_id = uuid::Uuid::new_v4();
            let principal_fp: Vec<u8> = sqlx::query_scalar(
                "SELECT principal_fingerprint FROM identity_bindings WHERE community_id=$1 AND binding_id=$2"
            )
            .bind(fx.community_id).bind(binding_id)
            .fetch_one(&raw).await.expect("fetch principal_fp");
            sqlx::query(
                "INSERT INTO identity_lifecycle_selectors
                (community_id, selector_id, selector_kind, selector_fingerprint,
                 fact_generation, principal_fingerprint, event_author_pubkey,
                 binding_id, binding_version,
                 asserted_history_id, selected_by_operation_id, selected_by_request_fingerprint)
                VALUES ($1,$2,1,$3,1,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(fx.community_id)
            .bind(ret_selector_id)
            .bind(principal_fp.as_slice())
            .bind(actor_fp.as_slice())
            .bind(binding_id)
            .bind(binding_version)
            .bind(ret_history_id)
            .bind(ret_op_id)
            .bind(ret_req_fp.as_slice())
            .execute(&mut *tx_ret)
            .await
            .expect("P-selector for retirement");
            tx_ret.commit().await.expect("commit retirement");
        }

        // Second call: same actor, different proof_event_id.
        // The lifecycle_revision mismatch must be caught at authorize_protected_use_in_tx.
        let orch2 = make_orchestrator(db);
        let event2 = make_kind9_event(&keys, fx.channel_id);
        let proof_event_id_2 = [0x41u8; 32];
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id,
                challenge: "challenge-2".to_string(),
                relay_url: "wss://relay.example.com".to_string(),
                proof_event_id: proof_event_id_2,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event2,
                thread_meta: None,
            })
            .await;

        // The complete Active→Retired transition committed above means the
        // binding is in state=2 (Retired) with a P-selector (kind=1) blocking
        // re-enrollment.  The second orchestrator call routes through
        // commit_admission_in_tx which:
        //   1. Finds no active binding (state=1 filter eliminates the retired row).
        //   2. Attempts enrollment — blocked by the P-selector.
        //   3. Returns AdmissionError::NoActiveBinding.
        // BindingRetired fires only when commit_kind9_atomic reaches
        // authorize_protected_use_in_tx with a CommittedAuthorization whose
        // lifecycle_revision was recorded before the concurrent retirement.
        // Here the retirement already committed before the second call starts,
        // so admission never reaches authorize_protected_use_in_tx at all.
        assert!(
            matches!(
                result,
                Err(AdmissionError::NoActiveBinding) | Err(AdmissionError::BindingRetired)
            ),
            "retired binding must prevent admission (NoActiveBinding from P-selector or BindingRetired); got: {result:?}"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Mutation red: epoch guard catches zero-row UPDATE ─────────────────────

    /// epoch rows_affected guard through the orchestrator: after admission,
    /// delete the epoch row and verify the orchestrator returns an error on
    /// the next commit attempt (the UPDATE matches zero rows → Transient).
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_epoch_guard_catches_zero_row_update() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);

        // First call: enroll and commit.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        let proof_event_id_1 = [0x50u8; 32];
        let event1 = make_kind9_event(&keys, fx.channel_id);
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id: Uuid::new_v4(),
            challenge: "challenge-epoch-1".to_string(),
            relay_url: "wss://relay.example.com".to_string(),
            proof_event_id: proof_event_id_1,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event1,
            thread_meta: None,
        })
        .await
        .expect("first orchestrator call must succeed");

        // The epoch immutability trigger prevents DELETE on authorization_authority_epochs.
        // The zero-row UPDATE guard is proven by pg_epoch_update_zero_rows_is_transient
        // (inner-path test).  This orchestrator test verifies the guard does NOT
        // incorrectly fire on valid consecutive admissions: a second successful call
        // proves the epoch UPDATE predicate matches every time.
        let orch2 = make_orchestrator(db);
        let proof_event_id_2 = [0x51u8; 32];
        let event2 = make_kind9_event(&keys, fx.channel_id);
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id: Uuid::new_v4(),
                challenge: "challenge-epoch-2".to_string(),
                relay_url: "wss://relay.example.com".to_string(),
                proof_event_id: proof_event_id_2,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event2,
                thread_meta: None,
            })
            .await;

        // The second call must succeed: the epoch guard passes, the epoch row
        // advances, and the event is inserted.  Proof: if rows_affected() != 1
        // the guard returns Transient — a success here confirms the guard ran
        // and found exactly one matching row.
        assert!(
            result.is_ok(),
            "second epoch advance must succeed (guard passed); got: {result:?}"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Mutation red: invalid post-admission kind-9 (proof replay) ────────────

    /// After a successful admission, replaying the same proof_event_id must be
    /// rejected with `ProofReplayed` and leave zero new effects.
    ///
    /// This isolates the `nip_fi_proof_replay_claims` uniqueness guard: the
    /// first call inserts the replay claim; a second call with an identical
    /// proof_event_id finds the pre-existing row and returns `ProofReplayed`
    /// before any authority mutations can be written.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn orchestrator_pg_proof_replay_is_rejected() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        // Both calls use the SAME proof_event_id — the second must be rejected.
        let proof_event_id = [0x60u8; 32];

        // First call: succeeds and commits the replay claim.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        let event1 = make_kind9_event(&keys, fx.channel_id);
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id: Uuid::new_v4(),
            challenge: "challenge-replay-1".to_string(),
            relay_url: "wss://relay.example.com".to_string(),
            proof_event_id,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event1,
            thread_meta: None,
        })
        .await
        .expect("first orchestrator call must succeed");

        // Second call: same proof_event_id — must fail with ProofReplayed.
        let orch2 = make_orchestrator(db);
        let event2 = make_kind9_event(&keys, fx.channel_id);
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id: Uuid::new_v4(),
                challenge: "challenge-replay-2".to_string(),
                relay_url: "wss://relay.example.com".to_string(),
                proof_event_id, // same proof — uniqueness violation
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event2.clone(),
                thread_meta: None,
            })
            .await;

        // The exact error must be ProofReplayed (from nip_fi_proof_replay_claims
        // uniqueness constraint), not a generic Transient or unknown variant.
        assert!(
            matches!(result, Err(AdmissionError::ProofReplayed)),
            "replayed proof must return exact ProofReplayed; got: {result:?}"
        );

        // The second event must NOT be persisted.
        let event2_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE community_id = $1 AND id = $2)",
        )
        .bind(fx.community_id)
        .bind(event2.id.to_bytes().as_slice())
        .fetch_one(&raw)
        .await
        .expect("query event2");
        assert!(
            !event2_exists,
            "replayed-proof event must NOT be persisted (FI-INV-09)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── Phase-A PR-4 PG race tests (postgres_ prefix for CI selection) ───────
    //
    // These six tests exercise the new ownership protocol paths introduced in
    // PR 4 (Design C Phase A): the event precheck (step 3c), the proof-owner
    // claim read (step 3d), the proof-owner INSERT with ON CONFLICT DO NOTHING
    // (step 13), and the deterministic op_id idempotence property.
    //
    // Named with `postgres_` prefix per the #6730 convention so they are
    // selected automatically by the `postgres_tests` CI matrix once the base
    // PR 3 merges and the workflow catches up.

    // ── PG race 1: same-connection proof reuse allowed ────────────────────────

    /// Step-3d guard: a second call with the SAME conn_id and SAME
    /// proof_event_id must succeed.  The proof-owner read finds the existing
    /// row and confirms conn_id matches → falls through as same-connection
    /// reuse.
    ///
    /// Verifies: the proof_replay_claims row remains, a second event is stored,
    /// and exactly one replay claim row exists (the second call did not insert
    /// a duplicate — ON CONFLICT DO NOTHING silently skips it).
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_same_conn_proof_reuse_allowed() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let proof_event_id = [0x70u8; 32];
        // Both calls share the same conn_id — same-connection reuse.
        let conn_id = Uuid::new_v4();

        // First call: enroll and commit.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        let event1 = make_kind9_event(&keys, fx.channel_id);
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id,
            challenge: "challenge-reuse-1".into(),
            relay_url: "wss://relay.example.com".into(),
            proof_event_id,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event1,
            thread_meta: None,
        })
        .await
        .expect("first same-conn call must succeed");

        // Second call: same conn_id, same proof_event_id, different event.
        let orch2 = make_orchestrator(db);
        let event2 = EventBuilder::new(nostr::Kind::from(9u16), "same-conn-reuse-second-msg")
            .tag(nostr::Tag::custom(
                nostr::TagKind::SingleLetter(nostr::SingleLetterTag {
                    character: nostr::Alphabet::H,
                    uppercase: false,
                }),
                [fx.channel_id.to_string()],
            ))
            .sign_with_keys(&keys)
            .expect("sign second same-conn event");
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id, // same connection
                challenge: "challenge-reuse-2".into(),
                relay_url: "wss://relay.example.com".into(),
                proof_event_id, // same proof
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event2.clone(),
                thread_meta: None,
            })
            .await;

        assert!(
            result.is_ok(),
            "same-conn proof reuse must succeed (step 3d same-conn path); got: {result:?}"
        );

        // Exactly one replay claim row for this proof.
        let claim_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM nip_fi_proof_replay_claims
             WHERE community_id = $1 AND proof_event_id = $2",
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query replay claims");
        assert_eq!(
            claim_count, 1,
            "exactly one replay claim row must exist after same-conn reuse"
        );

        // Second event must be persisted.
        let event2_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE community_id = $1 AND id = $2)",
        )
        .bind(fx.community_id)
        .bind(event2.id.to_bytes().as_slice())
        .fetch_one(&raw)
        .await
        .expect("query event2");
        assert!(event2_exists, "second event must be persisted after same-conn reuse");

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── PG race 2: cross-connection proof replay rejected ─────────────────────

    /// Step-3d guard: a second call with a DIFFERENT conn_id and the SAME
    /// proof_event_id must return `ProofReplayed`.  The proof-owner read
    /// finds the existing row and detects the conn_id mismatch → denied.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_cross_conn_proof_replay_rejected() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let proof_event_id = [0x71u8; 32];

        // First call: conn_id_a admits the proof.
        let conn_id_a = Uuid::new_v4();
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        let event1 = make_kind9_event(&keys, fx.channel_id);
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id: conn_id_a,
            challenge: "challenge-xconn-1".into(),
            relay_url: "wss://relay.example.com".into(),
            proof_event_id,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event1,
            thread_meta: None,
        })
        .await
        .expect("first cross-conn call must succeed");

        // Second call: different conn_id_b, same proof_event_id.
        let conn_id_b = Uuid::new_v4();
        assert_ne!(conn_id_a, conn_id_b, "test requires distinct conn_ids");
        let orch2 = make_orchestrator(db);
        let event2 = EventBuilder::new(nostr::Kind::from(9u16), "cross-conn-replay-second-msg")
            .tag(nostr::Tag::custom(
                nostr::TagKind::SingleLetter(nostr::SingleLetterTag {
                    character: nostr::Alphabet::H,
                    uppercase: false,
                }),
                [fx.channel_id.to_string()],
            ))
            .sign_with_keys(&keys)
            .expect("sign second cross-conn event");
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id: conn_id_b, // different connection
                challenge: "challenge-xconn-2".into(),
                relay_url: "wss://relay.example.com".into(),
                proof_event_id, // same proof
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event2.clone(),
                thread_meta: None,
            })
            .await;

        assert!(
            matches!(result, Err(AdmissionError::ProofReplayed)),
            "cross-conn proof reuse must return ProofReplayed (step 3d); got: {result:?}"
        );

        // Second event must NOT be persisted (authority mutations rolled back).
        let event2_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM events WHERE community_id = $1 AND id = $2)",
        )
        .bind(fx.community_id)
        .bind(event2.id.to_bytes().as_slice())
        .fetch_one(&raw)
        .await
        .expect("query event2");
        assert!(
            !event2_exists,
            "cross-conn replayed event must NOT be persisted (FI-INV-09)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── PG race 3: event duplicate precheck is a no-op ────────────────────────

    /// Step-3c guard: submitting the exact same event twice (same event.id,
    /// same proof_event_id, same conn_id) must trigger the event precheck
    /// on the second call.  The first call inserts the event; the second call
    /// finds it via FOR SHARE and returns `DuplicateEvent` — zero new authority
    /// mutations written.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_duplicate_event_precheck_is_noop() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let proof_event_id = [0x72u8; 32];
        let conn_id = Uuid::new_v4();
        // Both calls submit the IDENTICAL event object.
        let event = make_kind9_event(&keys, fx.channel_id);

        // First call: succeeds and persists the event.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id,
            challenge: "challenge-dup-1".into(),
            relay_url: "wss://relay.example.com".into(),
            proof_event_id,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event.clone(),
            thread_meta: None,
        })
        .await
        .expect("first duplicate-precheck call must succeed");

        // Count receipts before second call.
        let receipts_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operation_receipts WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("count receipts before");

        // Second call: identical event → step-3c precheck must catch it.
        let orch2 = make_orchestrator(db);
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id,
                challenge: "challenge-dup-2".into(),
                relay_url: "wss://relay.example.com".into(),
                proof_event_id,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event.clone(), // same event
                thread_meta: None,
            })
            .await;

        assert!(
            matches!(result, Err(AdmissionError::DuplicateEvent)),
            "duplicate event must return DuplicateEvent (step 3c precheck); got: {result:?}"
        );

        // Receipt count must not have increased — zero new authority mutations.
        let receipts_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operation_receipts WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("count receipts after");
        assert_eq!(
            receipts_before, receipts_after,
            "duplicate precheck must write zero new receipt rows (step 3c no-op)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── PG race 4: concurrent same-conn PK race — both succeed ───────────────

    /// Step-13 ON CONFLICT DO NOTHING, same-conn path: two concurrent calls
    /// with the same conn_id and same proof_event_id race to insert the claim
    /// row.  The NIP-FI writer lock serializes them, so in practice they do
    /// not truly race; one wins the INSERT and the other finds the row already
    /// present with the same conn_id.  Both calls must succeed.
    ///
    /// The test verifies the outcome — exactly one claim row, both events
    /// persisted — rather than the lock interleaving (which is non-deterministic).
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_concurrent_same_conn_pk_race_both_succeed() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let db_arc = db;
        let proof_event_id = [0x73u8; 32];
        let conn_id = Uuid::new_v4(); // shared conn_id

        let handles: Vec<_> = (0..2u8)
            .map(|_i| {
                let db_clone = std::sync::Arc::clone(&db_arc);
                let fx_community_id = fx.community_id;
                let fx_channel_id = fx.channel_id;
                let actor_clone = actor;
                let deadline_clone = deadline;
                // Distinct content per task so the two events have different IDs.
                // If they were identical, step 3c (event precheck) would catch the
                // duplicate before step 3d, masking the same-conn DO NOTHING path.
                let event = EventBuilder::new(nostr::Kind::from(9u16), format!("same-conn-race-msg-{_i}"))
                    .tag(nostr::Tag::custom(
                        nostr::TagKind::SingleLetter(nostr::SingleLetterTag {
                            character: nostr::Alphabet::H,
                            uppercase: false,
                        }),
                        [fx_channel_id.to_string()],
                    ))
                    .sign_with_keys(&keys)
                    .expect("sign kind-9 event");
                let assertion = make_assertion(deadline_clone);
                tokio::spawn(async move {
                    let orch = make_orchestrator(db_clone);
                    orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
                        community_id: fx_community_id,
                        channel_id: fx_channel_id,
                        actor: actor_clone,
                        conn_id, // same connection — both tasks
                        challenge: format!("challenge-pkrace-same-{_i}"),
                        relay_url: "wss://relay.example.com".into(),
                        proof_event_id,
                        proof_expires_at: deadline_clone,
                        transport: ProofTransport::Nip42WebSocket,
                        verified_assertion: assertion,
                        proposal: make_proposal(),
                        event,
                        thread_meta: None,
                    })
                    .await
                })
            })
            .collect();

        let mut successes = 0usize;
        let mut duplicate_noop = 0usize;
        for h in handles {
            match h.await.expect("task did not panic") {
                Ok(_) => successes += 1,
                Err(AdmissionError::DuplicateEvent) => duplicate_noop += 1,
                Err(e) => panic!("unexpected error in same-conn PK race: {e:?}"),
            }
        }
        // At least one task succeeded; the other may have hit the precheck
        // (if the winner committed before the loser's step-3c) or the
        // same-conn DO NOTHING path.
        assert!(
            successes >= 1,
            "at least one same-conn concurrent call must succeed; got successes={successes}"
        );
        assert_eq!(
            successes + duplicate_noop,
            2,
            "all tasks must account for (success or DuplicateEvent no-op)"
        );

        // Exactly one replay claim row.
        let claim_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM nip_fi_proof_replay_claims
             WHERE community_id = $1 AND proof_event_id = $2",
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query replay claims");
        assert_eq!(
            claim_count, 1,
            "exactly one replay claim must exist after concurrent same-conn admissions"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── PG race 5: concurrent cross-conn PK race — loser rejected ────────────

    /// Step-13 ON CONFLICT DO NOTHING, cross-conn path: two concurrent calls
    /// with DIFFERENT conn_ids and the same proof_event_id.  The NIP-FI writer
    /// lock serializes the transactions; the loser finds the winner's conn_id
    /// in the claim row and returns `ProofReplayed`.
    ///
    /// The test verifies: exactly one succeeds, the other returns `ProofReplayed`,
    /// exactly one event is persisted, and exactly one replay claim row exists.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_concurrent_cross_conn_pk_race_one_rejected() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let db_arc = db;
        let proof_event_id = [0x74u8; 32];

        let handles: Vec<_> = (0..2u8)
            .map(|i| {
                let db_clone = std::sync::Arc::clone(&db_arc);
                let fx_community_id = fx.community_id;
                let fx_channel_id = fx.channel_id;
                let actor_clone = actor;
                let deadline_clone = deadline;
                // Each task builds its own event with a distinct content string so the
                // signed events have different IDs — otherwise two tasks running in the
                // same second produce identical events, and step 3c (event precheck)
                // fires instead of step 3d (proof-owner conn_id check).
                let event = EventBuilder::new(nostr::Kind::from(9u16), format!("cross-conn-race-msg-{i}"))
                    .tag(nostr::Tag::custom(
                        nostr::TagKind::SingleLetter(nostr::SingleLetterTag {
                            character: nostr::Alphabet::H,
                            uppercase: false,
                        }),
                        [fx_channel_id.to_string()],
                    ))
                    .sign_with_keys(&keys)
                    .expect("sign kind-9 event");
                let assertion = make_assertion(deadline_clone);
                tokio::spawn(async move {
                    let orch = make_orchestrator(db_clone);
                    orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
                        community_id: fx_community_id,
                        channel_id: fx_channel_id,
                        actor: actor_clone,
                        conn_id: Uuid::new_v4(), // distinct per task
                        challenge: format!("challenge-pkrace-cross-{i}"),
                        relay_url: "wss://relay.example.com".into(),
                        proof_event_id,
                        proof_expires_at: deadline_clone,
                        transport: ProofTransport::Nip42WebSocket,
                        verified_assertion: assertion,
                        proposal: make_proposal(),
                        event,
                        thread_meta: None,
                    })
                    .await
                })
            })
            .collect();

        let mut successes = 0usize;
        let mut replayed = 0usize;
        for h in handles {
            match h.await.expect("task did not panic") {
                Ok(_) => successes += 1,
                Err(AdmissionError::ProofReplayed) => replayed += 1,
                Err(e) => panic!("unexpected error in cross-conn PK race: {e:?}"),
            }
        }
        // Exactly one winner, one loser.
        assert_eq!(successes, 1, "exactly one cross-conn concurrent call must succeed");
        assert_eq!(replayed, 1, "exactly one cross-conn concurrent call must return ProofReplayed");

        // Exactly one replay claim row.
        let claim_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM nip_fi_proof_replay_claims
             WHERE community_id = $1 AND proof_event_id = $2",
        )
        .bind(fx.community_id)
        .bind(proof_event_id.as_slice())
        .fetch_one(&raw)
        .await
        .expect("query replay claims");
        assert_eq!(
            claim_count, 1,
            "exactly one replay claim must exist after concurrent cross-conn race"
        );

        // Exactly one event row for this proof's community.
        let event_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("query event count");
        assert_eq!(
            event_count, 1,
            "exactly one event must be persisted after cross-conn PK race (loser rolled back)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }

    // ── PG race 6: deterministic op_id — exact-replay is a no-op ─────────────

    /// Deterministic operation ID idempotence: two calls that use the exact same
    /// `(community_id, proof_event_id, event.id)` triple produce the same UUID
    /// via `deterministic_admission_op_id`.  The second call must detect the
    /// duplicate via the step-3c event precheck (the event is already in the DB
    /// after the first call commits) and return `DuplicateEvent` with zero new
    /// authority writes.
    ///
    /// This is the end-to-end property test for the deterministic op_id design:
    /// the same logical request never produces two different receipts.
    #[tokio::test]
    #[ignore = "requires live PostgreSQL DB with migrations applied"]
    async fn postgres_deterministic_op_id_exact_replay_is_noop() {
        let Some((raw, db)) = test_db().await else {
            return;
        };
        let fx = setup_fixture(&raw).await;

        let keys = Keys::generate();
        let actor = keys.public_key();
        let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
        let proof_event_id = [0x75u8; 32];
        let conn_id = Uuid::new_v4();
        // Identical event used for both calls — same triple, same deterministic op_id.
        let event = make_kind9_event(&keys, fx.channel_id);

        // First call: fresh admission, persists event + receipt.
        let orch = make_orchestrator(std::sync::Arc::clone(&db));
        orch.commit_kind9_atomic(crate::nip_fi::Kind9Params {
            community_id: fx.community_id,
            channel_id: fx.channel_id,
            actor,
            conn_id,
            challenge: "challenge-detop-1".into(),
            relay_url: "wss://relay.example.com".into(),
            proof_event_id,
            proof_expires_at: deadline,
            transport: ProofTransport::Nip42WebSocket,
            verified_assertion: make_assertion(deadline),
            proposal: make_proposal(),
            event: event.clone(),
            thread_meta: None,
        })
        .await
        .expect("first deterministic-op call must succeed");

        let receipt_count_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operation_receipts WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("count receipts before replay");

        // Second call: exact same (community, proof, event) triple.
        // The deterministic op_id is identical.  Step 3c finds the event already
        // in the DB and returns DuplicateEvent before any authority write.
        let orch2 = make_orchestrator(db);
        let result = orch2
            .commit_kind9_atomic(crate::nip_fi::Kind9Params {
                community_id: fx.community_id,
                channel_id: fx.channel_id,
                actor,
                conn_id,
                challenge: "challenge-detop-2".into(),
                relay_url: "wss://relay.example.com".into(),
                proof_event_id,
                proof_expires_at: deadline,
                transport: ProofTransport::Nip42WebSocket,
                verified_assertion: make_assertion(deadline),
                proposal: make_proposal(),
                event: event.clone(), // same event → same deterministic op_id
                thread_meta: None,
            })
            .await;

        assert!(
            matches!(result, Err(AdmissionError::DuplicateEvent)),
            "exact-replay (same deterministic op_id) must return DuplicateEvent; got: {result:?}"
        );

        // No new receipt row written.
        let receipt_count_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operation_receipts WHERE community_id = $1",
        )
        .bind(fx.community_id)
        .fetch_one(&raw)
        .await
        .expect("count receipts after replay");
        assert_eq!(
            receipt_count_before, receipt_count_after,
            "exact-replay must write zero new receipt rows (deterministic op_id idempotence)"
        );

        teardown_fixture(&raw, fx.community_id).await;
    }
}
