-- 012_recovery: offline recovery state for Task 14.
--
-- recovery_intents is the durable local intent behind one offline
-- recovery idempotency key. It is written before the upstream
-- ContainWorkspace call so an ambiguous outcome (timeout, dropped
-- response, crash) reconciles by the same key without ever
-- re-containing the workspace. State moves pending -> contained ->
-- verified_empty -> completed, one step at a time; a crash resumes from
-- the recorded state.
--
-- recovery_events is the durable, non-secret record of each completed
-- offline recovery: which workspace, which founder, how many missions
-- the bulk containment covered, the containment generation, and the
-- digests that bind the event to the signed containment attestation.
-- No recovery-key material is ever stored here.

CREATE TABLE IF NOT EXISTS recovery_intents (
    workspace_id          TEXT NOT NULL,
    idempotency_key       TEXT NOT NULL,
    intent_id             TEXT NOT NULL,
    canonical_digest      TEXT NOT NULL,
    attestation_digest    TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL,
    state                 TEXT NOT NULL,
    containment_generation INTEGER NOT NULL DEFAULT 0,
    recovery_event_id     TEXT NOT NULL DEFAULT '',
    revoked_session_count INTEGER NOT NULL DEFAULT 0,
    contained_mission_count INTEGER NOT NULL DEFAULT 0,
    bootstrap_expires_at  TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (workspace_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS recovery_events (
    workspace_id          TEXT NOT NULL,
    event_id              TEXT NOT NULL,
    founder_id            TEXT NOT NULL,
    idempotency_key       TEXT NOT NULL,
    contained_mission_count INTEGER NOT NULL,
    containment_generation INTEGER NOT NULL,
    attestation_digest    TEXT NOT NULL,
    recovery_proof_digest TEXT NOT NULL,
    bootstrap_code_hash   TEXT NOT NULL,
    occurred_at           TEXT NOT NULL,
    PRIMARY KEY (workspace_id, event_id)
);

-- One completed recovery per idempotency key: concurrent resets race on
-- this constraint instead of double-recording the reset.
CREATE UNIQUE INDEX IF NOT EXISTS recovery_events_workspace_idempotency
    ON recovery_events (workspace_id, idempotency_key);
