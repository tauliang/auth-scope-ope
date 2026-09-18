import type {
  ApprovalBeginResponse,
  ApprovalFinishRequest,
  ApprovalResult,
  BootstrapBeginRequest,
  BootstrapBeginResponse,
  BootstrapCompleteRequest,
  BootstrapRecoveryBeginRequest,
  BootstrapRecoveryBeginResponse,
  BootstrapRegisterBeginRequest,
  BootstrapRegisterFinishResponse,
  BootstrapResponse,
  CeremonyBeginResponse,
  CeremonyFinishRequest,
  CLIAuthorizationApproveBeginResponse,
  GitHubBeginRequest,
  GitHubBeginResponse,
  GitHubConnection,
  GitHubFinishRequest,
  GitHubIssueResponse,
  MissionPassDraftCreateRequest,
  MissionPassDraftReviseRequest,
  MissionPassReview,
  ProblemResponse,
  SessionResponse,
} from './generated';

// ApiError is raised for non-2xx local API responses. When the server
// answers with application/problem+json, title carries the server's
// human-readable reason; it never contains credential or challenge
// material.
export class ApiError extends Error {
  readonly status: number;
  readonly title: string;
  constructor(status: number, message: string, title?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.title = title ?? message;
  }
}

// problemTitle extracts the problem title from a failed response, if any.
async function problemTitle(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.json()) as Partial<ProblemResponse>;
    return typeof body.title === 'string' ? body.title : undefined;
  } catch {
    return undefined;
  }
}

// request performs a same-origin JSON request. Credentials are never sent
// cross-origin: every OPE API call is same-origin by construction, and the
// client refuses to attach cookies elsewhere.
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  /* v8 ignore next -- defensive: all call sites use compile-time local paths */
  if (!path.startsWith('/')) {
    throw new Error(`refusing non-local API path: ${path}`);
  }
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    ...init,
  });
  if (!res.ok) {
    const title = await problemTitle(res);
    throw new ApiError(
      res.status,
      `request to ${path} failed with status ${res.status}`,
      title,
    );
  }
  return (await res.json()) as T;
}

// jsonRequest performs a same-origin JSON request with a body, attaching
// the session CSRF token when held. Used by state-changing calls.
function jsonRequest<T>(
  method: string,
  path: string,
  body: unknown,
  extraHeaders?: Record<string, string>,
): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (csrfToken !== null) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  if (extraHeaders) {
    for (const [name, value] of Object.entries(extraHeaders)) {
      headers[name] = value;
    }
  }
  return request<T>(path, { method, headers, body: JSON.stringify(body) });
}

// postJson performs a same-origin JSON POST. The server requires exactly
// application/json. When a session CSRF token is held in memory it is
// attached as X-CSRF-Token; extra headers (such as Idempotency-Key) may be
// supplied per call.
function postJson<T>(path: string, body: unknown, extraHeaders?: Record<string, string>): Promise<T> {
  return jsonRequest<T>('POST', path, body, extraHeaders);
}

// csrfToken is the session-bound CSRF token held in memory for the page
// lifetime. It is never written to browser storage.
let csrfToken: string | null = null;

// setCsrfToken stores the session CSRF token in memory after login, or
// clears it on logout. State-changing requests attach it automatically.
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

// newIdempotencyKey mints a unique key per mutating call so retried
// requests replay instead of duplicating the operation.
export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// fetchBootstrap loads the first-paint product state.
export function fetchBootstrap(): Promise<BootstrapResponse> {
  return request<BootstrapResponse>('/api/v1/bootstrap');
}

// fetchHealth checks process liveness.
export function fetchHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/healthz');
}

// authBootstrapBegin opens the enrollment ceremony with the terminal code.
export function authBootstrapBegin(code: string): Promise<BootstrapBeginResponse> {
  const body: BootstrapBeginRequest = { code };
  return postJson<BootstrapBeginResponse>('/api/v1/bootstrap/begin', body);
}

// authBootstrapRegisterBegin issues WebAuthn creation options inside the
// enrollment ceremony.
export function authBootstrapRegisterBegin(displayName?: string): Promise<CeremonyBeginResponse> {
  const body: BootstrapRegisterBeginRequest = displayName ? { display_name: displayName } : {};
  return postJson<CeremonyBeginResponse>('/api/v1/auth/register/begin', body);
}

// authBootstrapRegisterFinish verifies the attestation response.
export function authBootstrapRegisterFinish(
  ceremonyId: string,
  response: unknown,
): Promise<BootstrapRegisterFinishResponse> {
  const body: CeremonyFinishRequest = { ceremony_id: ceremonyId, response };
  return postJson<BootstrapRegisterFinishResponse>('/api/v1/auth/register/finish', body);
}

// authBootstrapRecoveryBegin starts the independent recovery method.
export function authBootstrapRecoveryBegin(
  method: 'passkey' | 'offline_key',
): Promise<BootstrapRecoveryBeginResponse> {
  const body: BootstrapRecoveryBeginRequest = { method };
  return postJson<BootstrapRecoveryBeginResponse>('/api/v1/bootstrap/recovery/begin', body);
}

// authBootstrapComplete confirms the recovery method and creates the
// first founder session, returning the session-bound CSRF token.
export function authBootstrapComplete(recoveryConfirmation?: string): Promise<SessionResponse> {
  const body: BootstrapCompleteRequest =
    recoveryConfirmation !== undefined ? { recovery_confirmation: recoveryConfirmation } : {};
  return postJson<SessionResponse>('/api/v1/bootstrap/complete', body);
}

// authLoginBegin issues WebAuthn request options for the enrolled founder.
export function authLoginBegin(): Promise<CeremonyBeginResponse> {
  return postJson<CeremonyBeginResponse>('/api/v1/auth/login/begin', {});
}

// authLoginFinish verifies the assertion and rotates the founder session,
// returning the session-bound CSRF token.
export function authLoginFinish(ceremonyId: string, response: unknown): Promise<SessionResponse> {
  const body: CeremonyFinishRequest = { ceremony_id: ceremonyId, response };
  return postJson<SessionResponse>('/api/v1/auth/login/finish', body);
}

// githubBegin opens the AuthScope-hosted installation handoff for one
// owner/name repository. The response carries the handoff ID and the
// fixed-origin installation URL; the upstream binding code never reaches
// the browser.
export function githubBegin(repository: string): Promise<GitHubBeginResponse> {
  const body: GitHubBeginRequest = { repository };
  return postJson<GitHubBeginResponse>('/api/v1/connections/github/begin', body, {
    'Idempotency-Key': newIdempotencyKey(),
  });
}

// githubFinish completes the handoff whose redirect the server already
// recorded, persisting the repository connection.
export function githubFinish(handoffId: string): Promise<GitHubConnection> {
  const body: GitHubFinishRequest = {};
  return postJson<GitHubConnection>(
    `/api/v1/connections/github/${encodeURIComponent(handoffId)}/finish`,
    body,
    { 'Idempotency-Key': newIdempotencyKey() },
  );
}

// githubIssue imports the trusted issue snapshot for a connection,
// paired with the workflow-posture check that gates launch.
export function githubIssue(connectionId: string, issueNumber: number): Promise<GitHubIssueResponse> {
  return request<GitHubIssueResponse>(
    `/api/v1/connections/github/${encodeURIComponent(connectionId)}/issues/${issueNumber}`,
  );
}

// createMissionPassDraft shapes and creates the exact AuthScope proposal
// for one issue, returning the review payload. The same idempotency key
// retried returns the same pass instead of duplicating it. A 202 payload
// carries reconciliation "pending": the upstream outcome stayed
// ambiguous and the same request can be retried.
export function createMissionPassDraft(
  body: MissionPassDraftCreateRequest,
  idempotencyKey?: string,
): Promise<MissionPassReview> {
  return postJson<MissionPassReview>('/api/v1/mission-passes/drafts', body, {
    'Idempotency-Key': idempotencyKey ?? newIdempotencyKey(),
  });
}

// reviseMissionPassDraft narrows the two editable draft limits (earlier
// expiry, lower aggregate budget) and returns the new immutable
// revision. Any other edit is rejected by the server.
export function reviseMissionPassDraft(
  passId: string,
  body: MissionPassDraftReviseRequest,
  idempotencyKey?: string,
): Promise<MissionPassReview> {
  return jsonRequest<MissionPassReview>(
    'PUT',
    `/api/v1/mission-passes/${encodeURIComponent(passId)}/draft`,
    body,
    { 'Idempotency-Key': idempotencyKey ?? newIdempotencyKey() },
  );
}

// fetchMissionPass reads one mission pass for founder review.
export function fetchMissionPass(passId: string): Promise<MissionPassReview> {
  return request<MissionPassReview>(`/api/v1/mission-passes/${encodeURIComponent(passId)}`);
}

// beginMissionPassApproval starts the one-use passkey decision ceremony.
// The server binds the challenge to the exact proposal revision; the
// browser supplies no binding or authority fields. The returned options
// are opaque to the client and feed the WebAuthn call.
export function beginMissionPassApproval(
  passId: string,
  idempotencyKey?: string,
): Promise<ApprovalBeginResponse> {
  return postJson<ApprovalBeginResponse>(
    `/api/v1/mission-passes/${encodeURIComponent(passId)}/approve/begin`,
    {},
    { 'Idempotency-Key': idempotencyKey ?? newIdempotencyKey() },
  );
}

// finishMissionPassApproval completes the ceremony with the credential
// assertion. On success the exact proposal is approved and only the
// mission is created. A 202 payload means the upstream outcome stayed
// ambiguous; the returned review carries reconciliation "pending" and
// the pass can be re-read to reconcile the recorded operation.
export function finishMissionPassApproval(
  passId: string,
  challengeId: string,
  assertion: unknown,
  idempotencyKey?: string,
): Promise<ApprovalResult | MissionPassReview> {
  const body: ApprovalFinishRequest = { challenge_id: challengeId, assertion };
  return postJson<ApprovalResult | MissionPassReview>(
    `/api/v1/mission-passes/${encodeURIComponent(passId)}/approve/finish`,
    body,
    { 'Idempotency-Key': idempotencyKey ?? newIdempotencyKey() },
  );
}

// isApprovalResult narrows the ambiguous finish union: a 200 carries the
// mission result, a 202 carries the pending review.
export function isApprovalResult(value: ApprovalResult | MissionPassReview): value is ApprovalResult {
  return typeof (value as ApprovalResult).mission_ref === 'string';
}

// beginCliAuthorization starts the one-use passkey decision ceremony for a
// CLI launch authorization. The server binds the challenge to the exact
// proposal values pinned at create time; the browser supplies no binding
// or authority fields. The returned options are opaque to the client and
// feed the WebAuthn call.
export function beginCliAuthorization(
  authorizationId: string,
  idempotencyKey?: string,
): Promise<CLIAuthorizationApproveBeginResponse> {
  return postJson<CLIAuthorizationApproveBeginResponse>(
    `/api/v1/cli/authorizations/${encodeURIComponent(authorizationId)}/approve/begin`,
    {},
    { 'Idempotency-Key': idempotencyKey ?? newIdempotencyKey() },
  );
}

// finishCliAuthorization completes the CLI decision ceremony with the
// credential assertion. On success the server answers 302 to the exact
// loopback callback bound at create time; fetch follows it so the one-use
// code is delivered to the waiting CLI, and the loopback callback answers
// "Return to the CLI". The code, verifier, and sealed runtime material are
// never exposed to the page.
export async function finishCliAuthorization(
  authorizationId: string,
  challengeId: string,
  assertion: unknown,
  idempotencyKey?: string,
): Promise<void> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (csrfToken !== null) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  headers['Idempotency-Key'] = idempotencyKey ?? newIdempotencyKey();
  const body: ApprovalFinishRequest = { challenge_id: challengeId, assertion };
  const path = `/api/v1/cli/authorizations/${encodeURIComponent(authorizationId)}/approve/finish`;
  /* v8 ignore next -- defensive: all call sites use compile-time local paths */
  if (!path.startsWith('/')) {
    throw new Error(`refusing non-local API path: ${path}`);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
    body: JSON.stringify(body),
    redirect: 'follow',
  });
  if (!res.ok) {
    const title = await problemTitle(res);
    throw new ApiError(
      res.status,
      `request to ${path} failed with status ${res.status}`,
      title,
    );
  }
}
