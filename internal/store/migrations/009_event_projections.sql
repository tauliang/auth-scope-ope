-- Task 10: durable event-projection state, the server-owned reconciliation
-- worker lease, revocation intents, and CLI revocation handoffs.
--
-- mission_projections holds one row per pass: the durable event cursor
-- plus the compatibility gate. compatible=0 blocks business mutations
-- until a parser and pinned-contract upgrade replays from the unchanged
-- cursor. The cursor advances only with a stored known event, in the same
-- transaction.
CREATE TABLE IF NOT EXISTS mission_projections (
    workspace_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    cursor TEXT NOT NULL DEFAULT '',
    event_seq INTEGER NOT NULL DEFAULT 0,
    mission_version INTEGER NOT NULL DEFAULT 0,
    compatible INTEGER NOT NULL DEFAULT 1,
    stale INTEGER NOT NULL DEFAULT 0,
    incompatibility_reason TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, pass_id)
);

-- worker_leases holds the server-owned reconciliation worker lease: one
-- row per instance. The worker holds it while running so a second
-- process cannot own the same instance cursor. Acquisition replaces the
-- row only when the stored lease expired; release deletes only the
-- row the owner still holds.
CREATE TABLE IF NOT EXISTS worker_leases (
    instance_id TEXT NOT NULL PRIMARY KEY,
    owner TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- revocation_intents is the durable local intent behind one revocation
-- idempotency key. It is written before the upstream RevokeMission call
-- so an ambiguous outcome reconciles by the original key without ever
-- re-issuing the revocation.
CREATE TABLE IF NOT EXISTS revocation_intents (
    workspace_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    reason_code TEXT NOT NULL DEFAULT '',
    canonical_digest TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'in_flight',
    containment TEXT NOT NULL DEFAULT '',
    attestation_digest TEXT NOT NULL DEFAULT '',
    attestation_json TEXT NOT NULL DEFAULT '',
    upstream_ref TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, pass_id)
);
CREATE INDEX IF NOT EXISTS idx_revocation_intents_key ON revocation_intents (workspace_id, idempotency_key);

-- cli_revocations holds result-only loopback PKCE revocation requests.
-- Only hashes of secret values are stored: the raw code and verifier
-- never reach the store. The token exchange returns only the opaque
-- result reference plus the fixed containment state; no credential or
-- session is issued or stored.
CREATE TABLE IF NOT EXISTS cli_revocations (
    workspace_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    state TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    canonical_digest TEXT NOT NULL,
    reason_code TEXT NOT NULL DEFAULT '',
    result_ref TEXT NOT NULL DEFAULT '',
    result_containment TEXT NOT NULL DEFAULT '',
    code_hash TEXT NOT NULL DEFAULT '',
    result_consumed_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_cli_revocations_state ON cli_revocations (workspace_id, pass_id, state);
CREATE INDEX IF NOT EXISTS idx_cli_revocations_code ON cli_revocations (workspace_id, code_hash);

-- Containment records the last known upstream revocation containment on
-- the pass: acknowledged, pending, or partial. Pending containment is
-- reconciled by the server-owned worker.
ALTER TABLE mission_passes ADD COLUMN containment TEXT NOT NULL DEFAULT '';
