-- Task 8: one-use browser PKCE handoff for CLI launch authorization.
-- cli_authorizations holds pending authorizations opened by the CLI. Only
-- hashes of secret values are stored: the raw verifier and code never
-- reach the store. The original state is kept so the finish step can
-- redirect it to the loopback callback; the signed decision attestation
-- lives only in process memory.
CREATE TABLE IF NOT EXISTS cli_authorizations (
    workspace_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    pass_id TEXT NOT NULL,
    state TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    ephemeral_public_key TEXT NOT NULL,
    proposal_digest TEXT NOT NULL,
    invocation_digest TEXT NOT NULL,
    agent_kit_id TEXT NOT NULL,
    agent_kit_version TEXT NOT NULL,
    runner_arguments_json TEXT NOT NULL DEFAULT '[]',
    mission_ref TEXT NOT NULL,
    mission_version INTEGER NOT NULL,
    canonical_request_digest BLOB NOT NULL,
    decision_challenge_id TEXT NOT NULL DEFAULT '',
    decision_attestation_digest TEXT NOT NULL DEFAULT '',
    code_hash BLOB,
    approved_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, authorization_id)
);
CREATE INDEX IF NOT EXISTS idx_cli_authorizations_state ON cli_authorizations (workspace_id, pass_id, state);
-- One logical CLI operation carries one client-generated state: concurrent
-- duplicate creates race on this constraint, and the loser replays the
-- winner when the canonical request digest matches.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cli_authorizations_state ON cli_authorizations (workspace_id, pass_id, state);
