-- Task 7: approval creates only the mission. The new mission_passes columns
-- hold the created mission and the signed approval decision; run_id stays
-- empty on approval. The approval_intents table is the durable local intent
-- behind one approval idempotency key, written before the upstream call so
-- an ambiguous outcome can be reconciled without re-issuing approval.
ALTER TABLE mission_passes ADD COLUMN mission_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN mission_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN approval_decision_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN attestation_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN run_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS approval_intents (
    workspace_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation_ref TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'in_flight',
    challenge_id TEXT NOT NULL DEFAULT '',
    attestation_digest TEXT NOT NULL DEFAULT '',
    attestation_json TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, pass_id)
);
CREATE INDEX IF NOT EXISTS idx_approval_intents_key ON approval_intents (workspace_id, idempotency_key);
