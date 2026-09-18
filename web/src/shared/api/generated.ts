// Code generated from openapi/ope-v1.yaml by scripts/generate-web-client.mjs.
// Do not edit by hand; run `node scripts/generate-web-client.mjs` instead.

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
  workspace?: WorkspaceBinding;
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

export interface SessionResponse {
  csrf_token: string;
}

export interface WorkspaceBinding {
  hostname: string;
  workspace_id: string;
}

