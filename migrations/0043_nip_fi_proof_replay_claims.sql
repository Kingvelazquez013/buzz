-- NIP-FI proof replay-claim table.
--
-- One row per (community_id, proof_event_id) pair that has been admitted.
-- A duplicate INSERT is the replay-detection signal; the primary key
-- constraint `nip_fi_proof_replay_claims_pkey` on (community_id,
-- proof_event_id) is the exact constraint name mapped to ProofReplayed in the
-- Rust admission path. No other 23505 maps to ProofReplayed (FI-INV-14).
--
-- retained_until: proof freshness deadline (assertion upstream authority
-- deadline). Rows may be pruned after this timestamp; the constraint remains
-- the authoritative replay guard until then.
--
-- This relation is a security ledger: append-only (no UPDATE/DELETE/TRUNCATE),
-- referenced by community_id provenance only, and excluded from write-fence
-- and community-deletion purge paths (same posture as identity_bindings).

CREATE TABLE nip_fi_proof_replay_claims (
    community_id    UUID NOT NULL REFERENCES communities(id),
    proof_event_id  BYTEA NOT NULL CHECK (octet_length(proof_event_id) = 32),
    retained_until  TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (community_id, proof_event_id)
);

CREATE INDEX nip_fi_proof_replay_claims_retention
    ON nip_fi_proof_replay_claims (retained_until);

CREATE FUNCTION nip_fi_proof_replay_claims_immutable_v1() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'nip_fi_proof_replay_claims is append-only'
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER nip_fi_proof_replay_claims_no_update_delete
    BEFORE UPDATE OR DELETE ON nip_fi_proof_replay_claims
    FOR EACH ROW EXECUTE FUNCTION nip_fi_proof_replay_claims_immutable_v1();
CREATE TRIGGER nip_fi_proof_replay_claims_no_truncate
    BEFORE TRUNCATE ON nip_fi_proof_replay_claims
    FOR EACH STATEMENT EXECUTE FUNCTION nip_fi_reject_truncate_v1();

-- Widen write-fence exclusion: proof replay claims are security ledger rows
-- and must not be purged on community deletion or fencing.
--
-- NOTE: This CREATE OR REPLACE must carry forward every table already listed
-- in migration 0042's definition.  The full set is the union of all exclusions
-- declared across migrations 0041, 0042, and 0043.
CREATE OR REPLACE FUNCTION community_write_fence_excluded_table(target NAME) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT target::TEXT = ANY (ARRAY[
        -- deletion control plane (0001+)
        'community_deletion_requests', 'community_deletion_approvals',
        'community_deletion_checkpoints', 'community_serving_write_leases',
        'community_deletion_executor_heartbeats', 'product_feedback',
        'rate_limit_violations',
        -- NIP-FI identity foundation (0041)
        'authorization_operation_receipts', 'identity_enrollment_policies',
        'identity_bindings', 'identity_lifecycle_history',
        'identity_lifecycle_selectors',
        -- NIP-FI authorization foundation (0042)
        'authorization_invalidation_domains', 'authorization_invalidation_floors',
        'authorization_authority_epochs', 'protected_object_authority',
        'authorization_event_capacity', 'authorization_events',
        'authorization_authentication_denial_attempts',
        'authorization_operation_version_delta_manifests',
        'authorization_operation_version_deltas', 'authorization_admission_results',
        -- NIP-FI proof replay ledger (0043)
        'nip_fi_proof_replay_claims'
    ]::TEXT[])
$$;
