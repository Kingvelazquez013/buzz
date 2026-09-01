-- NIP-FI proof replay-claim: add connection_id owner column.
--
-- Each proof claim now records the WebSocket connection UUID that first
-- admitted the proof event, enabling per-connection ownership checks at
-- admission time.  The primary key remains (community_id, proof_event_id)
-- and that constraint name remains the exact string mapped to
-- AdmissionError::ProofReplayed in the Rust admission path.
--
-- A claim is inserted only during final admission (never at AUTH), after
-- all other authority mutations succeed.  The append-only immutability
-- trigger from migration 0043 continues to hold: once a row is committed,
-- connection_id cannot be changed.
--
-- This column enables the amended Design C ownership protocol:
--   1. SELECT connection_id FOR SHARE on (community_id, proof_event_id)
--   2. Same conn_id → same-connection reuse, continue
--   3. Different conn_id → ProofReplayed (cross-connection reuse)
--   4. No row → proceed; INSERT this row at step 9 of commit_admission_body

ALTER TABLE nip_fi_proof_replay_claims
    ADD COLUMN IF NOT EXISTS connection_id UUID NOT NULL;
