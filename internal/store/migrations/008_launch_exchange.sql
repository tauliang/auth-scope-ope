-- Task 9: exactly-once exchange of one approved authorization code for one
-- upstream launch preparation. Each row is keyed by the SHA-256 of the
-- decoded authorization code; only digests and run metadata are stored.
-- The sealed signed envelope, the signed decision attestation, and any
-- credential bytes never reach durable storage: the envelope digest and
-- the attestation digest are the only cryptographic traces kept.
CREATE TABLE IF NOT EXISTS launch_exchange_intents (
    workspace_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    envelope_digest TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_launch_exchange_intents_updated
    ON launch_exchange_intents (workspace_id, updated_at);
