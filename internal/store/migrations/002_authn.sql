-- 002_authn: founder authentication state for Task 3.
--
-- Sessions gain a CSRF token hash: every established-session browser
-- mutation must present the session-bound CSRF token. Bootstrap codes are
-- one-use terminal codes; only their SHA-256 hashes are stored. Offline
-- recovery key hashes back the offline recovery flow (a later task); the
-- browser never sees them again after enrollment.

ALTER TABLE sessions ADD COLUMN csrf_token_hash TEXT NOT NULL DEFAULT '';

-- One-use bootstrap codes. Only the SHA-256 hash of the code is stored;
-- the raw code is printed once to the controlling terminal.
CREATE TABLE IF NOT EXISTS bootstrap_codes (
    workspace_id TEXT NOT NULL,
    code_hash    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT,
    PRIMARY KEY (workspace_id, code_hash)
);

-- Offline recovery key hashes, one per founder. The raw key is displayed
-- once during enrollment and confirmed by proof of possession; only the
-- hash persists.
CREATE TABLE IF NOT EXISTS offline_recovery_keys (
    workspace_id TEXT NOT NULL,
    founder_id   TEXT NOT NULL,
    key_hash     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (workspace_id, founder_id)
);
