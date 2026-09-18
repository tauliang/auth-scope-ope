-- 004_mission_pass_proposal: exact AuthScope proposal fields on mission
-- passes.
--
-- The pass row carries AuthScope's returned proposal ID, algorithm-tagged
-- proposal and invocation digests, fixed agent-kit identity, ordered
-- runner arguments, pinned source identifiers, the generated mission
-- branch, the trusted snapshot content for review, and the two editable
-- limits. ApprovedProposalDigest stays empty until approval copies the
-- approved value. Reconciliation tracks whether the last upstream proposal
-- mutation has a known outcome. No credential material is stored here.
ALTER TABLE mission_passes ADD COLUMN connection_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN issue_number INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mission_passes ADD COLUMN repository_name TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN proposal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN proposal_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN approved_proposal_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN source_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN source_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN base_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN mission_branch TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN agent_kit_id TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN agent_kit_version TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN runner_arguments TEXT NOT NULL DEFAULT '[]';
ALTER TABLE mission_passes ADD COLUMN invocation_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN max_aggregate_cost_micros INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mission_passes ADD COLUMN objective TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN acceptance_criteria TEXT NOT NULL DEFAULT '[]';
ALTER TABLE mission_passes ADD COLUMN shaped_draft_json TEXT NOT NULL DEFAULT '';
ALTER TABLE mission_passes ADD COLUMN reconciliation TEXT NOT NULL DEFAULT 'settled';
