-- 001_initial: workspace-qualified OPE presentation store.
--
-- Every primary or unique business key begins with workspace_id, so one
-- workspace's records can never be read or written through another
-- workspace's key. The store holds references, passkey public credentials,
-- hashed sessions, event cursors, and idempotency results. It never holds
-- GitHub tokens, AuthScope refresh tokens, private keys, raw issue bodies,
-- patches, agent transcripts, or receipt secrets.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Singleton instance binding, written once at startup before HTTP serving.
-- Only workload_identity_digest may change, exactly once, via a conditional
-- update while it is still empty.
CREATE TABLE IF NOT EXISTS instance (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id                TEXT NOT NULL,
    workspace_id               TEXT NOT NULL,
    hostname                   TEXT NOT NULL,
    origin                     TEXT NOT NULL,
    rp_id                      TEXT NOT NULL,
    session_cookie_name        TEXT NOT NULL,
    workload_identity_digest   TEXT NOT NULL DEFAULT '',
    created_at                 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS founders (
    workspace_id TEXT NOT NULL,
    founder_id   TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    PRIMARY KEY (workspace_id, founder_id)
);

-- Passkey public credentials. Stores public key material only; private key
-- material never reaches OPE.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    workspace_id  TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    founder_id    TEXT NOT NULL,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, credential_id),
    FOREIGN KEY (workspace_id, founder_id) REFERENCES founders (workspace_id, founder_id)
);

-- Local sessions. Stores the session hash, never the raw session token.
CREATE TABLE IF NOT EXISTS sessions (
    workspace_id TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    founder_id   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, session_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS sessions_workspace_hash_idx
    ON sessions (workspace_id, session_hash);

-- GitHub connections hold only the AuthScope repository-binding reference
-- and immutable repository identity. No GitHub token or App private key.
CREATE TABLE IF NOT EXISTS github_connections (
    workspace_id           TEXT NOT NULL,
    connection_id          TEXT NOT NULL,
    repository_binding_ref TEXT NOT NULL,
    repository_id          INTEGER NOT NULL,
    repository_name        TEXT NOT NULL DEFAULT '',
    created_at             TEXT NOT NULL,
    PRIMARY KEY (workspace_id, connection_id)
);

-- Mission passes. store_revision is the local compare-and-swap token and
-- increments on every mutation; draft_version is the founder-visible
-- proposal revision; authscope_mission_version is the upstream authority
-- version. Neither draft nor upstream version is used as the CAS token.
CREATE TABLE IF NOT EXISTS mission_passes (
    workspace_id            TEXT NOT NULL,
    pass_id                 TEXT NOT NULL,
    store_revision          INTEGER NOT NULL,
    draft_version           INTEGER NOT NULL,
    authscope_mission_version INTEGER NOT NULL DEFAULT 0,
    state                   TEXT NOT NULL DEFAULT 'draft',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (workspace_id, pass_id)
);

-- Projected mission events, appended idempotently by workspace-qualified
-- event ID.
CREATE TABLE IF NOT EXISTS mission_events (
    workspace_id TEXT NOT NULL,
    pass_id      TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    cursor       TEXT NOT NULL DEFAULT '',
    payload      TEXT NOT NULL DEFAULT '',
    occurred_at  TEXT NOT NULL,
    ingested_at  TEXT NOT NULL,
    PRIMARY KEY (workspace_id, pass_id, event_id)
);
CREATE INDEX IF NOT EXISTS mission_events_cursor_idx
    ON mission_events (workspace_id, pass_id, cursor);

CREATE TABLE IF NOT EXISTS expansions (
    workspace_id TEXT NOT NULL,
    expansion_id TEXT NOT NULL,
    pass_id      TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'requested',
    created_at   TEXT NOT NULL,
    PRIMARY KEY (workspace_id, expansion_id)
);

-- Idempotency records keyed by workspace-qualified key. status is
-- 'inflight' or 'completed'; result holds the opaque completed result.
CREATE TABLE IF NOT EXISTS idempotency_records (
    workspace_id     TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    canonical_digest TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'inflight',
    result           BLOB,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (workspace_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS telemetry_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id TEXT NOT NULL,
    name         TEXT NOT NULL,
    occurred_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS telemetry_events_name_idx
    ON telemetry_events (workspace_id, name);
