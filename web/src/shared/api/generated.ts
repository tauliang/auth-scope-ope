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

