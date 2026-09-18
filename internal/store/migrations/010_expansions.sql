-- Task 11: local expansion projections and durable expansion decision
-- intents.
--
-- The 001 schema created a stub expansions table. This migration adds
-- the columns the expansion decision service needs: the table holds
-- the exact canonical expansion delta for one upstream expansion
-- request. It is the single source of truth the browser reads: the row
-- is synced from the authoritative upstream delta and verified against
-- the expansion digest before it is stored. Only allowlisted canonical
-- fields are stored; unknown fields are rejected, never retained. The
-- unique pending index enforces one pending expansion per mission: a
-- second simultaneous pending expansion is a conflict.
ALTER TABLE expansions ADD COLUMN mission_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE expansions ADD COLUMN delta_json TEXT NOT NULL DEFAULT '';
ALTER TABLE expansions ADD COLUMN expansion_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE expansions ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_expansions_pass ON expansions (workspace_id, pass_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_expansions_pending_per_mission
    ON expansions (workspace_id, mission_ref)
    WHERE status = 'pending';

-- expansion_intents is the durable local intent behind one expansion
-- decision idempotency key. It is written before the upstream
-- DecideExpansion call so an ambiguous outcome reconciles by the
-- original key without ever re-issuing the decision.
CREATE TABLE IF NOT EXISTS expansion_intents (
    workspace_id TEXT NOT NULL,
    expansion_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT '',
    canonical_digest TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'in_flight',
    attestation_digest TEXT NOT NULL DEFAULT '',
    attestation_json TEXT NOT NULL DEFAULT '',
    upstream_ref TEXT NOT NULL DEFAULT '',
    result_mission_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, expansion_id)
);
CREATE INDEX IF NOT EXISTS idx_expansion_intents_key ON expansion_intents (workspace_id, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_expansion_intents_state ON expansion_intents (workspace_id, state);
