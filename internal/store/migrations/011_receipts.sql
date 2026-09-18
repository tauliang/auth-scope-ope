-- Task 12: verified receipt projections and GitHub check publication
-- intents. The raw signed envelope is never persisted: receipt_views
-- holds only the receipt digest and the fixed verified fields, and
-- check_publications holds the publication intent keyed by the
-- derived idempotency key.

CREATE TABLE IF NOT EXISTS receipt_views (
	workspace_id TEXT NOT NULL,
	pass_id TEXT NOT NULL,
	verification TEXT NOT NULL,
	reason_code TEXT NOT NULL DEFAULT '',
	receipt_id TEXT NOT NULL DEFAULT '',
	grant_id TEXT NOT NULL DEFAULT '',
	mission_ref TEXT NOT NULL DEFAULT '',
	key_id TEXT NOT NULL DEFAULT '',
	signed_at TEXT NOT NULL DEFAULT '',
	receipt_digest TEXT NOT NULL DEFAULT '',
	settlement_digest TEXT NOT NULL DEFAULT '',
	outcome TEXT NOT NULL DEFAULT '',
	mission_versions_json TEXT NOT NULL DEFAULT '[]',
	expansion_decision_refs_json TEXT NOT NULL DEFAULT '[]',
	repository_id INTEGER NOT NULL DEFAULT 0,
	issue_number INTEGER NOT NULL DEFAULT 0,
	branch TEXT NOT NULL DEFAULT '',
	pull_request_number INTEGER NOT NULL DEFAULT 0,
	head_sha TEXT NOT NULL DEFAULT '',
	checks_json TEXT NOT NULL DEFAULT '[]',
	started_at TEXT NOT NULL DEFAULT '',
	finished_at TEXT NOT NULL DEFAULT '',
	aggregate_cost_micros INTEGER NOT NULL DEFAULT 0,
	budget_micros INTEGER NOT NULL DEFAULT 0,
	historical_enforcement_json TEXT NOT NULL DEFAULT '[]',
	verified_at TEXT NOT NULL,
	PRIMARY KEY (workspace_id, pass_id)
);

CREATE TABLE IF NOT EXISTS check_publications (
	workspace_id TEXT NOT NULL,
	pass_id TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	receipt_digest TEXT NOT NULL DEFAULT '',
	repository_id INTEGER NOT NULL DEFAULT 0,
	pull_request_number INTEGER NOT NULL DEFAULT 0,
	head_sha TEXT NOT NULL DEFAULT '',
	binding_id TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL DEFAULT 'in_flight',
	check_run_id TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (workspace_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_check_publications_pass
	ON check_publications (workspace_id, pass_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_check_publications_state
	ON check_publications (workspace_id, state, updated_at);

-- The pass-owned receipt loop needs a durable marker for the upstream
-- receipt-ready signal: the pass stays in outcome_pending until the
-- worker verifies the receipt locally.
ALTER TABLE mission_passes ADD COLUMN receipt_pending_at TEXT NOT NULL DEFAULT '';
