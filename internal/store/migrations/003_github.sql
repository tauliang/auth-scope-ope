-- 003_github: GitHub handoff state, extended connection fields, and
-- workflow-posture checks.
--
-- Handoff rows track the opaque AuthScope-hosted installation handoff:
-- only the SHA-256 hash of the 256-bit state and, after the callback,
-- only the SHA-256 digest of the one-use binding code are stored. The
-- raw binding code lives only in a bounded in-memory cache until finish,
-- restart, or expiry.
CREATE TABLE IF NOT EXISTS github_handoffs (
    workspace_id         TEXT NOT NULL,
    handoff_id           TEXT NOT NULL,
    session_id           TEXT NOT NULL,
    state_hash           TEXT NOT NULL,
    upstream_handoff_id  TEXT NOT NULL DEFAULT '',
    binding_code_digest  TEXT NOT NULL DEFAULT '',
    authscope_origin     TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    callback_at          TEXT,
    consumed_at          TEXT,
    PRIMARY KEY (workspace_id, handoff_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS github_handoffs_id_idx
    ON github_handoffs (handoff_id);

-- Connections persist the verified AuthScope repository-binding
-- reference plus immutable repository identity. No GitHub token, App
-- private key, or OAuth material is stored here.
ALTER TABLE github_connections ADD COLUMN installation_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE github_connections ADD COLUMN permission_status TEXT NOT NULL DEFAULT '';
ALTER TABLE github_connections ADD COLUMN verified_at TEXT NOT NULL DEFAULT '';

-- Workflow-posture checks persist only the posture digest, the inspected
-- head SHA, the outcome, reason codes, and expiry. Rechecked before
-- launch; never stores workflow file contents.
CREATE TABLE IF NOT EXISTS github_posture_checks (
    workspace_id   TEXT NOT NULL,
    connection_id  TEXT NOT NULL,
    ref            TEXT NOT NULL,
    posture_digest TEXT NOT NULL,
    head_sha       TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    reason_codes   TEXT NOT NULL DEFAULT '[]',
    expires_at     TEXT NOT NULL,
    checked_at     TEXT NOT NULL,
    PRIMARY KEY (workspace_id, connection_id, ref)
);
CREATE INDEX IF NOT EXISTS github_posture_checks_conn_idx
    ON github_posture_checks (workspace_id, connection_id, checked_at);
