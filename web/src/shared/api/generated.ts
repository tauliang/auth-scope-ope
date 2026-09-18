// Code generated from openapi/ope-v1.yaml by scripts/generate-web-client.mjs.
// Do not edit by hand; run `node scripts/generate-web-client.mjs` instead.

export interface ApprovalBeginResponse {
  challenge_id: string;
  options: unknown;
}

export interface ApprovalFinishRequest {
  assertion: unknown;
  challenge_id: string;
}

export interface ApprovalResult {
  approval_decision_ref: string;
  authscope_mission_version: number;
  mission_hash: string;
  mission_ref: string;
  workspace_id: string;
}

export interface BootstrapBeginRequest {
  code: string;
}

export interface BootstrapBeginResponse {
  expires_at: string;
}

export interface BootstrapCompleteRequest {
  recovery_confirmation?: string;
}

export interface BootstrapRecoveryBeginRequest {
  method: "passkey" | "offline_key";
}

export interface BootstrapRecoveryBeginResponse {
  ceremony_id?: string;
  method: "passkey" | "offline_key";
  options?: unknown;
  recovery_key?: string;
}

export interface BootstrapRegisterBeginRequest {
  display_name?: string;
}

export interface BootstrapRegisterFinishResponse {
  credential_id: string;
}

export interface BootstrapResponse {
  authority_labels: string[];
  compatibility: CompatibilityStatus;
  enrolled: boolean;
  enrollment_state: "needs_bootstrap" | "needs_recovery_method" | "locked" | "authenticated";
  telemetry_state: "enabled" | "disabled";
  workspace?: WorkspaceBinding;
}

export interface CLIAuthorizationApproveBeginResponse {
  agent_kit_id: string;
  agent_kit_version: string;
  assertion_options: unknown;
  challenge_id: string;
  invocation_digest: string;
  issue_number: number;
  pass_id: string;
  proposal_digest: string;
  repository_name: string;
  runner_arguments: string[];
}

export interface CLIAuthorizationCreateRequest {
  code_challenge: string;
  code_challenge_method: "S256";
  ephemeral_public_key: string;
  pass_id: string;
  redirect_uri: string;
  state: string;
}

export interface CLIAuthorizationCreateResponse {
  agent_kit_id: string;
  agent_kit_version: string;
  authorization_id: string;
  browser_url: string;
  invocation_digest: string;
  proposal_digest: string;
  runner_arguments: string[];
}

export interface CLIRevocationCreateRequest {
  code_challenge: string;
  code_challenge_method: string;
  pass_id: string;
  redirect_uri: string;
  state: string;
}

export interface CLIRevocationCreateResponse {
  browser_url: string;
  request_id: string;
  revocation_digest: string;
}

export interface CLIRevocationExchangeRequest {
  code: string;
  code_verifier: string;
  redirect_uri: string;
  state: string;
}

export interface CLIRevocationExchangeResponse {
  containment: string;
  result_ref: string;
}

export interface CLITokenRequest {
  code: string;
  verifier: string;
}

export interface CLITokenResponse {
  mission_ref: string;
  run_id: string;
  sealed_envelope: string;
}

export interface CeremonyBeginResponse {
  ceremony_id: string;
  options: unknown;
}

export interface CeremonyFinishRequest {
  ceremony_id: string;
  response: unknown;
}

export interface CompatibilityStatus {
  core_version: string;
  problems?: string[];
  status: "ready" | "not_ready";
}

export interface ErrorResponse {
  error: string;
}

export interface ExpansionBeginResponse {
  challenge_id: string;
  decision: "approve_once" | "deny";
  effective_expiry: string;
  expansion_id: string;
  options: unknown;
}

export interface ExpansionDecideBeginRequest {
  decision: "approve_once" | "deny";
}

export interface ExpansionDecideFinishRequest {
  assertion: unknown;
  challenge_id: string;
}

export interface ExpansionDecidePendingResponse {
  decision: "approve_once" | "deny";
  expansion_id: string;
  reconciliation: string;
}

export interface ExpansionDecisionResult {
  authscope_mission_version?: number;
  decision: "approve_once" | "deny";
  decision_ref: string;
  expansion_id: string;
  pass_id: string;
  state?: string;
}

export interface ExpansionListResponse {
  expansions: PendingExpansion[];
  pass_id: string;
}

export interface GitHubBeginRequest {
  repository: string;
}

export interface GitHubBeginResponse {
  expires_at: string;
  handoff_id: string;
  installation_url: string;
}

export interface GitHubConnection {
  connection_id: string;
  installation_id: number;
  permission_status: string;
  repository_binding_id: string;
  repository_id: number;
  repository_name: string;
  verified_at: string;
  workspace_id: string;
}

export type GitHubFinishRequest = Record<string, never>;

export interface GitHubIssueResponse {
  posture: GitHubPosture;
  snapshot: GitHubIssueSnapshot;
}

export interface GitHubIssueSnapshot {
  acceptance_criteria: string[];
  base_sha: string;
  default_branch: string;
  installation_id: number;
  issue_number: number;
  objective: string;
  repository_binding_id: string;
  repository_full_name: string;
  repository_id: number;
  source_digest: string;
  source_revision: string;
  workspace_id: string;
}

export interface GitHubPosture {
  checked_at: string;
  expires_at: string;
  head_sha: string;
  outcome: "clean" | "risky";
  reason_codes: string[];
}

export interface HealthResponse {
  status: "ok";
}

export interface MissionPassDraftCreateRequest {
  connection_id: string;
  expires_at: string;
  issue_number: number;
  max_aggregate_cost_micros: number;
}

export interface MissionPassDraftReviseRequest {
  expected_draft_version: number;
  expected_store_revision: number;
  expires_at: string;
  max_aggregate_cost_micros: number;
}

export interface MissionPassLimits {
  expires_at: string;
  max_aggregate_cost_micros: number;
}

export interface MissionPassReview {
  acceptance_criteria: string[];
  agent_kit_id: string;
  agent_kit_version: string;
  approval_decision_ref?: string;
  approved_proposal_digest?: string;
  attestation_digest?: string;
  authscope_mission_version: number;
  base_sha?: string;
  connection_id: string;
  draft_version: number;
  invocation_digest: string;
  issue_number: number;
  limits: MissionPassLimits;
  mission_branch?: string;
  mission_hash?: string;
  mission_ref?: string;
  objective: string;
  pass_id: string;
  proposal_digest: string;
  proposal_id: string;
  reconciliation: "settled" | "pending";
  repository_name: string;
  run_id?: string;
  runner_arguments: string[];
  shaped_draft?: Record<string, never>;
  source_digest?: string;
  source_revision?: string;
  state: "draft" | "approved" | "launching" | "running" | "awaiting_expansion" | "outcome_pending" | "completed" | "failed" | "revoked" | "expired";
  store_revision: number;
  workspace_id: string;
}

export interface PendingExpansion {
  agent_rationale?: string;
  blocked_operation: string;
  budget_micros: number;
  consequence_change: string;
  current_authority: string;
  destination: string;
  expansion_digest: string;
  expansion_id: string;
  expired: boolean;
  normalized_arguments_digest: string;
  path: string;
  quantity: number;
  reason_code: string;
  ref: string;
  repository: string;
  requested_authority: string;
  requested_expiry: string;
  resource: string;
  reversibility: "reversible" | "irreversible";
  stale: boolean;
}

export interface ProblemResponse {
  detail?: string;
  status: number;
  title: string;
  type?: string;
}

export interface ReadyResponse {
  core_version: string;
  problems?: string[];
  status: "ready" | "not_ready";
}

export interface ReceiptCheckSummary {
  kind: string;
  outcome: string;
}

export interface ReceiptEnforcementSummary {
  level: string;
  scope: string;
}

export interface ReceiptPublicationStatus {
  check_run_id?: string;
  head_sha: string;
  idempotency_key: string;
  pull_request_number: number;
  repository_id: number;
  state: "in_flight" | "settled" | "disputed";
  updated_at: string;
}

export interface ReceiptStatus {
  pass_id: string;
  publication?: ReceiptPublicationStatus;
  reason_code?: "bad_signature" | "bad_key" | "bad_payload" | "bad_binding";
  verification: "pending" | "verified" | "unverifiable";
  view?: ReceiptView;
}

export interface ReceiptView {
  aggregate_cost_micros?: number;
  branch?: string;
  budget_micros?: number;
  checks?: ReceiptCheckSummary[];
  expansion_decision_refs?: string[];
  finished_at?: number;
  grant_id: string;
  head_sha?: string;
  historical_enforcement?: ReceiptEnforcementSummary[];
  issue_number?: number;
  key_id?: string;
  mission_ref: string;
  mission_versions?: number[];
  outcome: "success" | "failure";
  pull_request_number?: number;
  receipt_digest: string;
  receipt_id: string;
  repository_id?: number;
  settlement_digest?: string;
  signed_at?: number;
  started_at?: number;
  verification: string;
  workspace_id: string;
}

export interface RevocationResult {
  containment: string;
  mission_ref: string;
  pass_id: string;
  reason_code: string;
  revoked: boolean;
  revoked_at: string;
}

export interface RevokeBeginRequest {
  reason: string;
}

export interface RevokeBeginResponse {
  challenge_id: string;
  options: unknown;
}

export interface RevokeFinishRequest {
  assertion: unknown;
  challenge_id: string;
  cli_revocation_id?: string;
}

export interface RevokePendingResponse {
  pass_id: string;
  reconciliation: string;
}

export interface SessionResponse {
  csrf_token: string;
}

export interface TimelineEvent {
  authscope_mission_version: number;
  branch?: string;
  check_kind?: string;
  check_outcome?: string;
  cursor: string;
  event_id: string;
  head_sha?: string;
  occurred_at: string;
  pull_request_number?: number;
  reason_code?: string;
  resource_digest: string;
  type: string;
}

export interface TimelineResponse {
  compatible: boolean;
  containment: string;
  cursor: string;
  events: TimelineEvent[];
  incompatibility_reason?: string;
  pass_id: string;
  reconciliation: string;
  repository_name?: string;
  stale: boolean;
  state: string;
}

export interface WorkspaceBinding {
  hostname: string;
  workspace_id: string;
}

