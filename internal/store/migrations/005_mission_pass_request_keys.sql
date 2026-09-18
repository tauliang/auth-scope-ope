-- 005_mission_pass_request_keys: idempotency keys for draft-open
-- requests.
--
-- A draft-open POST carries a caller-supplied idempotency key. The first
-- request to claim (workspace_id, idempotency_key) owns the key and its
-- pass; a retried request with the same key resolves to the same pass
-- instead of opening a duplicate draft or issuing a duplicate upstream
-- proposal mutation. Keys map to passes, never to upstream results; the
-- pass row carries the reconciliation state.
CREATE TABLE IF NOT EXISTS mission_pass_request_keys (
    workspace_id    TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    pass_id         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (workspace_id, idempotency_key)
);
