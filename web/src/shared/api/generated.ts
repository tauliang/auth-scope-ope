// Code generated from openapi/ope-v1.yaml by scripts/generate-web-client.mjs.
// Do not edit by hand; run `node scripts/generate-web-client.mjs` instead.

export interface BootstrapResponse {
  authority_labels: string[];
  compatibility: CompatibilityStatus;
  enrolled: boolean;
  workspace?: WorkspaceBinding;
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

export interface ReadyResponse {
  core_version: string;
  problems?: string[];
  status: "ready" | "not_ready";
}

export interface WorkspaceBinding {
  hostname: string;
  workspace_id: string;
}

